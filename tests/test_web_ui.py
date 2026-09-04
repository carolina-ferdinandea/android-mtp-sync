"""Tests for the Flask web UI.

Covers the security guards (host allow-list, same-origin, path confinement)
across the whole route surface, the structured RunResult plumbing that replaced
log parsing, and the profile/rule/bookmark routes.
"""

import json
import pathlib
import shutil
import subprocess
import threading
import time

import pytest

pytest.importorskip("flask")

from phone_migration import config as cfg, device, runner, state, web_ui  # noqa: E402


ROOT = pathlib.Path(__file__).resolve().parent.parent
JS_DIR = ROOT / "phone_migration" / "static" / "js"
SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}

RESULT = {
    "dry_run": True,
    "profile": "pixel",
    "device": "Pixel 7",
    "stats": {"copied": 2, "renamed": 0, "deleted": 0, "errors": 0, "skipped": 1,
              "moved": 2, "synced": 0, "backed_up": 0, "resumed": 0, "folders": 1},
    "transfer": {"size_bytes": 10, "seconds": 0.5},
    "rules": [{
        "id": "r-0001", "mode": "move", "phone_path": "/DCIM", "desktop_path": "~/Pictures",
        "stats": {"copied": 2, "skipped": 1}, "error": None,
        "files": [{"action": "moved", "src": "a.jpg", "dst": "~/Pictures/a.jpg", "error": None}],
    }],
}

# Every route that can change state. The guard must cover all of them.
MUTATING_ROUTES = [
    ("post", "/api/profiles"),
    ("put", "/api/profiles/whatever"),
    ("delete", "/api/profiles/whatever"),
    ("post", "/api/rules"),
    ("delete", "/api/rules/whatever/r-0001"),
    ("post", "/api/run"),
    ("post", "/api/folder/create"),
    ("post", "/api/bookmarks/desktop"),
    ("delete", "/api/bookmarks/desktop/0"),
    ("post", "/api/tests/run"),
]


@pytest.fixture
def client(monkeypatch):
    """conftest already repoints HISTORY_FILE/BOOKMARKS_FILE/config at tmp_path."""
    monkeypatch.setattr(web_ui, "current_run_status",
                        {"running": False, "progress": 0, "logs": [], "result": None})
    monkeypatch.setattr(web_ui, "test_run_status",
                        {"running": False, "progress": 0, "logs": [],
                         "results": {"passed": 0, "failed": 0, "skipped": 0},
                         "failed_tests": []})
    web_ui.app.config["TESTING"] = True
    return web_ui.app.test_client()


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Confine the desktop browse/mkdir routes to tmp_path."""
    monkeypatch.setattr(web_ui, "ALLOWED_ROOTS", [tmp_path])
    monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda cls: tmp_path))
    return tmp_path


def fake_run(result=RESULT, line="Move: /DCIM -> ~/Pictures", gate=None, boom=None):
    """Build a stand-in for runner.run_for_connected_device."""
    def _run(config, **kwargs):
        print(line)
        if gate is not None:
            gate.wait(5)
        if boom is not None:
            raise boom
        return result
    return _run


def wait_idle(client, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not client.get("/api/run/status").get_json()["running"]:
            return client.get("/api/run/status").get_json()
        time.sleep(0.01)
    raise AssertionError("run never finished")


def _seed_profiles(*names):
    config = cfg.load_config()
    for name in names:
        cfg.add_profile(config, {"name": name, "device": {}, "rules": []})
    cfg.save_config(config)


@pytest.mark.parametrize("path", ["/", "/profiles", "/rules", "/history", "/documentation"])
def test_every_page_renders(client, path):
    assert client.get(path).status_code == 200


@pytest.mark.parametrize("path", ["/", "/profiles", "/rules", "/history"])
def test_every_page_can_show_alerts(client, path):
    body = client.get(path).get_data(as_text=True)
    assert body.count('id="alert-container"') == 1


# --------------------------------------------------------------------------
# same-origin guard (#10) - the whole mutating surface
# --------------------------------------------------------------------------

@pytest.mark.parametrize("method,path", MUTATING_ROUTES,
                         ids=[f"{m}{p}" for m, p in MUTATING_ROUTES])
def test_every_mutating_route_needs_same_origin(client, method, path):
    resp = getattr(client, method)(path, json={})
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Cross-origin request refused"


@pytest.mark.parametrize("method,path", MUTATING_ROUTES,
                         ids=[f"{m}{p}" for m, p in MUTATING_ROUTES])
def test_every_mutating_route_refuses_a_foreign_origin(client, method, path):
    resp = getattr(client, method)(path, json={}, headers={"Origin": "http://evil.example"})
    assert resp.status_code == 403


def test_get_needs_no_origin_header(client):
    assert client.get("/api/run/status").status_code == 200


def test_sec_fetch_site_same_origin_is_accepted(client, monkeypatch):
    monkeypatch.setattr(runner, "run_for_connected_device", fake_run())
    assert client.post("/api/run", json={}, headers=SAME_ORIGIN).status_code == 200
    wait_idle(client)


def test_sec_fetch_site_none_is_accepted(client, monkeypatch):
    monkeypatch.setattr(runner, "run_for_connected_device", fake_run())
    resp = client.post("/api/run", json={}, headers={"Sec-Fetch-Site": "none"})
    assert resp.status_code == 200
    wait_idle(client)


def test_matching_origin_header_is_accepted(client, monkeypatch):
    monkeypatch.setattr(runner, "run_for_connected_device", fake_run())
    resp = client.post("/api/run", json={}, headers={"Origin": "http://localhost"})
    assert resp.status_code == 200
    wait_idle(client)


def test_cross_site_sec_fetch_beats_a_spoofable_origin(client):
    """Sec-Fetch-Site: cross-site with no Origin must still be refused."""
    resp = client.post("/api/run", json={}, headers={"Sec-Fetch-Site": "cross-site"})
    assert resp.status_code == 403


def test_a_rebound_host_is_refused(client):
    """DNS rebinding: same-origin to the attacker's name is still not us."""
    resp = client.put("/api/profiles/x", json={"name": "y"},
                      base_url="http://evil.test", headers=SAME_ORIGIN)
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Bad host"


def test_a_rebound_host_is_refused_on_reads_too(client):
    assert client.get("/api/history", base_url="http://evil.test").status_code == 403


def test_start_web_ui_allows_its_own_host_and_port(monkeypatch):
    monkeypatch.setattr(web_ui, "ALLOWED_HOSTS", set(web_ui.ALLOWED_HOSTS))
    monkeypatch.setattr(web_ui.app, "run", lambda **kwargs: None)

    web_ui.start_web_ui(host="127.0.0.1", port=8123)

    assert "127.0.0.1:8123" in web_ui.ALLOWED_HOSTS
    assert "localhost:8123" in web_ui.ALLOWED_HOSTS


def test_no_cors_headers_are_advertised(client):
    assert "Access-Control-Allow-Origin" not in client.get("/api/history").headers


# --------------------------------------------------------------------------
# desktop path confinement (#11)
# --------------------------------------------------------------------------

def test_browse_desktop_outside_allowed_roots_is_refused(client, home):
    assert client.get("/api/browse/desktop?path=/etc").status_code == 403


def test_browse_desktop_traversal_is_refused(client, home):
    assert client.get(f"/api/browse/desktop?path={home}/../../etc").status_code == 403


def test_browse_desktop_inside_allowed_root_lists_entries(client, home):
    (home / "Pictures").mkdir()
    (home / "note.txt").write_text("x")
    body = client.get(f"/api/browse/desktop?path={home}").get_json()
    assert [e["name"] for e in body["entries"]] == ["Pictures", "note.txt"]
    assert body["entries"][0]["type"] == "dir"


def test_browse_desktop_reports_symlinks(client, home):
    (home / "real").mkdir()
    (home / "link").symlink_to(home / "real")
    body = client.get(f"/api/browse/desktop?path={home}").get_json()
    by_name = {e["name"]: e for e in body["entries"]}
    assert by_name["link"]["is_symlink"] is True
    assert by_name["real"]["is_symlink"] is False


def test_create_folder_rejects_traversal_segments(client, home):
    resp = client.post("/api/folder/create", json={"path": f"{home}/a/../../etc/x"},
                       headers=SAME_ORIGIN)
    assert resp.status_code == 400


def test_create_folder_outside_allowed_roots_is_refused(client, home):
    resp = client.post("/api/folder/create", json={"path": "/etc/x"}, headers=SAME_ORIGIN)
    assert resp.status_code == 403


def test_create_folder_makes_the_directory(client, home):
    resp = client.post("/api/folder/create", json={"path": str(home / "New Folder")},
                       headers=SAME_ORIGIN)
    assert resp.status_code == 200
    assert (home / "New Folder").is_dir()


def test_create_existing_folder_is_409(client, home):
    (home / "dup").mkdir()
    resp = client.post("/api/folder/create", json={"path": str(home / "dup")},
                       headers=SAME_ORIGIN)
    assert resp.status_code == 409


def test_a_nul_byte_in_a_path_is_a_400(client, home):
    assert client.get("/api/browse/desktop?path=%00").status_code == 400
    assert client.post("/api/folder/create", headers=SAME_ORIGIN,
                       json={"path": "\0"}).status_code == 400


def test_an_unresolvable_user_in_a_tilde_path_is_a_400(client, home):
    """Path("~nosuchuser1234/x").expanduser() raises RuntimeError, not
    ValueError - that must be a 400 too, not an unhandled 500."""
    assert client.get("/api/browse/desktop?path=~nosuchuser1234/x").status_code == 400


def test_add_rule_rejects_a_non_string_profile(client, home):
    resp = client.post("/api/rules", headers=SAME_ORIGIN, json={
        "profile": {"a": 1}, "mode": "copy",
        "phone_path": "/DCIM", "desktop_path": str(home / "Pictures")})
    assert resp.status_code == 400


def test_add_rule_outside_allowed_roots_is_refused(client, home):
    _seed_profiles("pixel")
    resp = client.post("/api/rules", headers=SAME_ORIGIN, json={
        "profile": "pixel", "mode": "copy",
        "phone_path": "/DCIM", "desktop_path": "/etc"})

    assert resp.status_code == 403
    assert cfg.find_profile(cfg.load_config(), "pixel")["rules"] == []


def test_add_rule_inside_an_allowed_root_is_accepted(client, home):
    _seed_profiles("pixel")
    resp = client.post("/api/rules", headers=SAME_ORIGIN, json={
        "profile": "pixel", "mode": "copy",
        "phone_path": "/DCIM", "desktop_path": str(home / "Pictures")})

    assert resp.status_code == 200
    assert len(cfg.find_profile(cfg.load_config(), "pixel")["rules"]) == 1


def test_add_backup_rule_is_accepted(client, home):
    _seed_profiles("pixel")
    resp = client.post("/api/rules", headers=SAME_ORIGIN, json={
        "profile": "pixel", "mode": "backup",
        "phone_path": "/DCIM", "desktop_path": str(home / "Pictures")})

    assert resp.status_code == 200
    assert cfg.find_profile(cfg.load_config(), "pixel")["rules"][0]["mode"] == "backup"


def test_delete_rule(client, home):
    _seed_profiles("pixel")
    client.post("/api/rules", headers=SAME_ORIGIN, json={
        "profile": "pixel", "mode": "copy",
        "phone_path": "/DCIM", "desktop_path": str(home / "Pictures")})
    rule_id = cfg.find_profile(cfg.load_config(), "pixel")["rules"][0]["id"]

    resp = client.delete(f"/api/rules/pixel/{rule_id}", headers=SAME_ORIGIN)
    assert resp.status_code == 200
    assert cfg.find_profile(cfg.load_config(), "pixel")["rules"] == []


# --------------------------------------------------------------------------
# bookmarks
# --------------------------------------------------------------------------

def test_bookmark_type_is_validated(client):
    assert client.get("/api/bookmarks/etc").status_code == 400


def test_desktop_bookmark_outside_allowed_roots_is_refused(client, home):
    resp = client.post("/api/bookmarks/desktop", headers=SAME_ORIGIN,
                       json={"name": "root", "path": "/etc"})
    assert resp.status_code == 403
    assert web_ui.bookmarks["desktop"] == []


def test_desktop_bookmark_inside_an_allowed_root_round_trips(client, home):
    (home / "Pictures").mkdir()
    resp = client.post("/api/bookmarks/desktop", headers=SAME_ORIGIN,
                       json={"name": "pics", "path": str(home / "Pictures")})

    assert resp.status_code == 200
    assert client.get("/api/bookmarks/desktop").get_json()["bookmarks"][0]["name"] == "pics"
    assert web_ui.BOOKMARKS_FILE.exists()


def test_phone_bookmarks_are_normalised_and_deletable(client):
    resp = client.post("/api/bookmarks/phone", headers=SAME_ORIGIN,
                       json={"name": "cam", "path": "/storage/emulated/0/DCIM"})
    assert resp.status_code == 200
    assert web_ui.bookmarks["phone"][0]["path"] == "internal/DCIM"

    assert client.delete("/api/bookmarks/phone/0", headers=SAME_ORIGIN).status_code == 200
    assert web_ui.bookmarks["phone"] == []


def test_phone_bookmark_uses_internal_alias_for_localized_storage(client, monkeypatch):
    monkeypatch.setattr(
        runner,
        "detect_connected_device",
        lambda *args, **kwargs: {"device": {"activation_uri": "mtp://sony/"}},
    )
    monkeypatch.setattr(
        web_ui,
        "_phone_alias_map",
        lambda _uri: {"Internal storage": "Interner gemeinsamer Speicher", "SD Card": "1234-5678"},
    )

    resp = client.post("/api/bookmarks/phone", headers=SAME_ORIGIN,
                       json={"name": "cam", "path": "/Interner gemeinsamer Speicher/DCIM"})
    assert resp.status_code == 200
    assert web_ui.bookmarks["phone"][0]["path"] == "internal/DCIM"


def test_browse_phone_resolves_internal_alias_to_localized_storage(client, monkeypatch):
    monkeypatch.setattr(
        runner,
        "detect_connected_device",
        lambda *args, **kwargs: {"device": {"activation_uri": "mtp://sony/"}},
    )
    monkeypatch.setattr(
        web_ui,
        "_phone_alias_map",
        lambda _uri: {"Internal storage": "Interner gemeinsamer Speicher"},
    )
    seen = {}

    def fake_list(_uri, phone_path="/"):
        seen["path"] = phone_path
        return []

    monkeypatch.setattr(web_ui.browser, "list_phone_directory", fake_list)
    resp = client.get("/api/browse/phone?path=internal/DCIM")

    assert resp.status_code == 200
    assert seen["path"] == "/Interner gemeinsamer Speicher/DCIM"


def test_desktop_bookmark_rejects_a_non_string_path(client, home):
    resp = client.post("/api/bookmarks/desktop", headers=SAME_ORIGIN,
                       json={"name": "pics", "path": {"a": 1}})
    assert resp.status_code == 400


def test_phone_bookmark_rejects_a_non_string_name(client):
    resp = client.post("/api/bookmarks/phone", headers=SAME_ORIGIN,
                       json={"name": {"a": 1}, "path": "/DCIM"})
    assert resp.status_code == 400


def test_deleting_an_unknown_bookmark_is_404(client):
    assert client.delete("/api/bookmarks/phone/7", headers=SAME_ORIGIN).status_code == 404


# --------------------------------------------------------------------------
# /api/run: one at a time (#20), structured result (#21, #22)
# --------------------------------------------------------------------------

def test_second_concurrent_run_is_refused(client, monkeypatch):
    gate = threading.Event()
    monkeypatch.setattr(runner, "run_for_connected_device", fake_run(gate=gate))
    try:
        assert client.post("/api/run", json={}, headers=SAME_ORIGIN).status_code == 200
        assert client.post("/api/run", json={}, headers=SAME_ORIGIN).status_code == 409
    finally:
        gate.set()
    wait_idle(client)


def test_status_reports_the_structured_result_and_live_logs(client, monkeypatch):
    monkeypatch.setattr(runner, "run_for_connected_device", fake_run())
    client.post("/api/run", json={"dry_run": True}, headers=SAME_ORIGIN)
    status = wait_idle(client)

    assert status["result"]["stats"]["copied"] == 2
    assert status["result"]["rules"][0]["files"][0]["action"] == "moved"
    assert status["result"]["dry_run"] is True
    assert "Move: /DCIM -> ~/Pictures" in status["logs"]
    assert status["progress"] == 100


def test_status_exposes_no_parsed_stats_key(client):
    """The regex stat parser is gone; the RunResult is the only stat source."""
    assert set(client.get("/api/run/status").get_json()) == {
        "running", "progress", "logs", "result"}


def test_logs_stream_while_the_run_is_still_going(client, monkeypatch):
    gate = threading.Event()
    monkeypatch.setattr(runner, "run_for_connected_device",
                        fake_run(line="first line", gate=gate))
    client.post("/api/run", json={}, headers=SAME_ORIGIN)
    try:
        deadline = time.time() + 5
        while time.time() < deadline:
            if "first line" in client.get("/api/run/status").get_json()["logs"]:
                break
            time.sleep(0.01)
        else:
            raise AssertionError("logs did not stream during the run")
    finally:
        gate.set()
    wait_idle(client)


def test_logs_are_ansi_stripped(client, monkeypatch):
    monkeypatch.setattr(runner, "run_for_connected_device",
                        fake_run(line="\033[38;2;1;2;3mcolored\033[0m"))
    client.post("/api/run", json={}, headers=SAME_ORIGIN)
    assert "colored" in wait_idle(client)["logs"]


def test_a_failed_run_keeps_its_logs_and_records_an_error(client, monkeypatch):
    monkeypatch.setattr(runner, "run_for_connected_device",
                        fake_run(boom=RuntimeError("mount vanished")))
    client.post("/api/run", json={}, headers=SAME_ORIGIN)
    status = wait_idle(client)

    assert status["result"] is None
    assert "Move: /DCIM -> ~/Pictures" in status["logs"]
    assert any("mount vanished" in line for line in status["logs"])
    assert web_ui.run_history[0]["status"] == "error"


def test_history_entry_carries_the_structured_result(client, monkeypatch):
    monkeypatch.setattr(runner, "run_for_connected_device", fake_run())
    client.post("/api/run", json={}, headers=SAME_ORIGIN)
    wait_idle(client)

    entry = web_ui.run_history[0]
    assert entry["profile"] == "pixel"
    assert entry["status"] == "success"
    assert entry["dry_run"] is True
    assert entry["rules_count"] == 1
    assert entry["stats"]["copied"] == 2
    assert entry["rules"][0]["files"][0]["src"] == "a.jpg"
    assert web_ui.HISTORY_FILE.exists()


def test_a_run_with_errors_is_recorded_as_error(client, monkeypatch):
    result = {**RESULT, "stats": {**RESULT["stats"], "errors": 1}}
    monkeypatch.setattr(runner, "run_for_connected_device", fake_run(result=result))
    client.post("/api/run", json={}, headers=SAME_ORIGIN)
    wait_idle(client)
    assert web_ui.run_history[0]["status"] == "error"


def test_rename_duplicates_is_tri_state(client, monkeypatch):
    seen = {}

    def spy(config, **kwargs):
        seen.update(kwargs)
        return RESULT

    monkeypatch.setattr(runner, "run_for_connected_device", spy)

    client.post("/api/run", json={}, headers=SAME_ORIGIN)
    wait_idle(client)
    assert seen["rename_duplicates"] is None       # let each mode keep its default

    client.post("/api/run", json={"rename_duplicates": False}, headers=SAME_ORIGIN)
    wait_idle(client)
    assert seen["rename_duplicates"] is False

    client.post("/api/run", json={"rename_duplicates": True}, headers=SAME_ORIGIN)
    wait_idle(client)
    assert seen["rename_duplicates"] is True


def test_a_run_with_no_rules_has_no_transfer_block(client, monkeypatch):
    """`transfer` is None whenever no rule ran: nothing may index into it."""
    empty = {"dry_run": False, "profile": "p", "device": "d", "transfer": None,
             "stats": {k: 0 for k in ("copied", "renamed", "deleted", "errors",
                                      "skipped", "moved", "synced", "backed_up",
                                      "resumed", "folders")},
             "rules": []}
    monkeypatch.setattr(runner, "run_for_connected_device", fake_run(result=empty))
    client.post("/api/run", json={}, headers=SAME_ORIGIN)
    status = wait_idle(client)

    assert status["result"]["transfer"] is None
    assert status["result"]["rules"] == []
    assert client.get("/api/history").status_code == 200

    entry = web_ui.run_history[0]
    assert entry["status"] == "success"
    assert entry["rules"] == []
    assert entry["rules_count"] == 0
    assert entry["dry_run"] is False


def test_no_javascript_indexes_the_transfer_block():
    """`result.transfer` is None for a no-rules run; only guarded reads are safe."""
    for name in ("dashboard.js", "history.js"):
        source = (JS_DIR / name).read_text(encoding="utf-8")
        assert "transfer." not in source
        assert "transfer[" not in source


def test_a_failed_history_write_still_clears_running(client, monkeypatch):
    def boom():
        raise TypeError("Object of type set is not JSON serializable")

    monkeypatch.setattr(runner, "run_for_connected_device", fake_run())
    monkeypatch.setattr(web_ui, "save_history", boom)

    client.post("/api/run", json={}, headers=SAME_ORIGIN)
    wait_idle(client)                              # a stuck `running` is a permanent 409

    assert client.post("/api/run", json={}, headers=SAME_ORIGIN).status_code == 200
    wait_idle(client)


# --------------------------------------------------------------------------
# fix round 1: /api/run and /api/tests/run share one lock
# --------------------------------------------------------------------------

@pytest.fixture
def connected(monkeypatch):
    """A device is present, so /api/tests/run gets past its precondition."""
    monkeypatch.setattr(runner, "detect_connected_device",
                        lambda config, verbose=False: {"name": "pixel", "device": {}})


def test_tests_are_refused_while_a_run_is_going(client, connected, monkeypatch):
    gate = threading.Event()
    monkeypatch.setattr(runner, "run_for_connected_device", fake_run(gate=gate))
    try:
        assert client.post("/api/run", json={}, headers=SAME_ORIGIN).status_code == 200
        resp = client.post("/api/tests/run", json={}, headers=SAME_ORIGIN)
        assert resp.status_code == 409
        assert web_ui.test_run_status["running"] is False
    finally:
        gate.set()
    wait_idle(client)


def test_a_busy_device_beats_the_no_device_error(client, monkeypatch):
    """No `connected` fixture: the busy check must fire before the gio probe."""
    gate = threading.Event()
    monkeypatch.setattr(runner, "run_for_connected_device", fake_run(gate=gate))
    monkeypatch.setattr(runner, "detect_connected_device",
                        lambda *a, **k: pytest.fail("probed the device mid-run"))
    try:
        assert client.post("/api/run", json={}, headers=SAME_ORIGIN).status_code == 200
        assert client.post("/api/tests/run", json={},
                           headers=SAME_ORIGIN).status_code == 409
    finally:
        gate.set()
    wait_idle(client)


def test_a_run_is_refused_while_the_tests_are_going(client, connected, monkeypatch):
    gate = threading.Event()
    monkeypatch.setattr(web_ui, "_test_worker", lambda *a: gate.wait(5))
    try:
        assert client.post("/api/tests/run", json={}, headers=SAME_ORIGIN).status_code == 200
        resp = client.post("/api/run", json={}, headers=SAME_ORIGIN)
        assert resp.status_code == 409
        assert web_ui.current_run_status["running"] is False
    finally:
        gate.set()


def test_tests_status_hands_back_a_copy_of_the_logs(client):
    """jsonify iterates `logs` while the worker thread appends to it."""
    source = (ROOT / "phone_migration" / "web_ui.py").read_text(encoding="utf-8")
    handler = source.split("def api_test_status():")[1].split("@app.route")[0]
    assert 'list(test_run_status["logs"])' in handler
    assert "jsonify(test_run_status)" not in source

    web_ui.test_run_status["logs"].append("first")
    assert client.get("/api/tests/status").get_json()["logs"] == ["first"]


def test_the_test_button_stays_disabled_during_a_run():
    """dashboard.html re-enables it every second; a run has to win that race."""
    source = (ROOT / "phone_migration" / "web_templates" / "dashboard.html").read_text()
    body = source.split("function updateTestButton()")[1].split("}")[0]
    assert "isRunning" in body


# --------------------------------------------------------------------------
# fix round 1: private-use glyphs never reach the browser
# --------------------------------------------------------------------------

def test_nerd_font_glyphs_are_stripped_from_the_log_stream(client, monkeypatch):
    """theme.Icons picks private-use codepoints from the terminal env; a
    browser renders those as tofu."""
    monkeypatch.setattr(runner, "run_for_connected_device",
                        fake_run(line="\uf10b  Phone"))
    client.post("/api/run", json={}, headers=SAME_ORIGIN)
    assert "Phone" in wait_idle(client)["logs"]


def test_supplementary_private_use_glyphs_are_stripped_too(client, monkeypatch):
    monkeypatch.setattr(runner, "run_for_connected_device",
                        fake_run(line="\U000f0001 Connected"))
    client.post("/api/run", json={}, headers=SAME_ORIGIN)
    assert "Connected" in wait_idle(client)["logs"]


def test_indentation_survives_glyph_stripping(client, monkeypatch):
    monkeypatch.setattr(runner, "run_for_connected_device",
                        fake_run(line="  \uf111 Phone not connected"))
    client.post("/api/run", json={}, headers=SAME_ORIGIN)
    assert "  Phone not connected" in wait_idle(client)["logs"]


# --------------------------------------------------------------------------
# fix round 2: \r-animated spinner frames never reach the browser (or
# history.json) as one giant line; every direct logs.append also scrubs
# --------------------------------------------------------------------------

def test_streaming_output_collapses_carriage_returns_to_the_last_frame():
    """A spinner overwrites its line with \\r; only the final frame should
    survive as a single log line."""
    lines = []
    web_ui.StreamingOutput(lines).write("\r| a\r/ a\r- a\n")
    assert lines == ["- a"]


def test_test_worker_scrubs_subprocess_output(monkeypatch, tmp_path):
    """_test_worker used to append raw subprocess lines, bypassing the
    ANSI/private-use scrubbing StreamingOutput gives /api/run."""
    class FakeStdout:
        def __init__(self, lines):
            self._lines = iter(lines)

        def readline(self):
            return next(self._lines, '')

    class FakeProcess:
        def __init__(self, lines):
            self.stdout = FakeStdout(lines)
            self.returncode = 0

        def wait(self):
            pass

    line = "\ue000 PASSED test_x \U0001F600\n"
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: FakeProcess([line]))
    monkeypatch.setitem(web_ui.test_run_status, "logs", [])
    monkeypatch.setitem(web_ui.test_run_status, "results",
                        {"passed": 0, "failed": 0, "skipped": 0})
    monkeypatch.setitem(web_ui.test_run_status, "failed_tests", [])

    web_ui._test_worker(tmp_path / "dummy_test.py", tmp_path)

    logs = web_ui.test_run_status["logs"]
    assert "\ue000" not in "\n".join(logs)
    assert any("PASSED test_x" in entry and "\U0001F600" in entry for entry in logs)
    assert web_ui.test_run_status["results"]["passed"] == 1


# --------------------------------------------------------------------------
# fix round 1: minors
# --------------------------------------------------------------------------

def test_a_non_string_path_is_a_400(client, home):
    """A JSON object where a path belongs must not be an unhandled 500."""
    for junk in ({"a": 1}, ["x"], 7):
        resp = client.post("/api/folder/create", json={"path": junk}, headers=SAME_ORIGIN)
        assert resp.status_code == 400, junk


def test_a_non_string_rule_path_is_a_400(client, home):
    _seed_profiles("pixel")
    resp = client.post("/api/rules", headers=SAME_ORIGIN, json={
        "profile": "pixel", "mode": "copy",
        "phone_path": "/DCIM", "desktop_path": {"a": 1}})
    assert resp.status_code == 400


def test_an_origin_on_another_scheme_is_refused(client):
    """https://localhost is a different origin from http://localhost."""
    resp = client.post("/api/run", json={}, headers={"Origin": "https://localhost"})
    assert resp.status_code == 403


def test_a_matching_scheme_and_host_is_accepted(client, monkeypatch):
    monkeypatch.setattr(runner, "run_for_connected_device", fake_run())
    resp = client.post("/api/run", json={}, headers={"Origin": "http://localhost"})
    assert resp.status_code == 200
    wait_idle(client)


# --------------------------------------------------------------------------
# history storage
# --------------------------------------------------------------------------

def test_history_limit_is_clamped(client):
    web_ui.run_history.extend({"timestamp": str(i)} for i in range(120))

    assert len(client.get("/api/history?limit=-1").get_json()) == 1
    assert len(client.get("/api/history?limit=0").get_json()) == 1
    assert len(client.get("/api/history?limit=5000").get_json()) == 100
    assert len(client.get("/api/history").get_json()) == 10


def test_history_lives_beside_the_config():
    """conftest repoints the module constants, so assert on how they are built."""
    source = (ROOT / "phone_migration" / "web_ui.py").read_text(encoding="utf-8")
    assert 'HISTORY_FILE = cfg.CONFIG_DIR / "history.json"' in source
    assert 'BOOKMARKS_FILE = cfg.CONFIG_DIR / "bookmarks.json"' in source


def test_old_format_history_entries_still_load(client):
    """Entries written before RunResult have no `rules`/`dry_run` keys."""
    web_ui.HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    web_ui.HISTORY_FILE.write_text(json.dumps([
        {"timestamp": "2026-01-01T00:00:00", "profile": "old", "rules_count": 2,
         "status": "success", "stats": {"moved": 1}, "logs": ["a line"]}
    ]))

    web_ui.load_history()

    entry = client.get("/api/history").get_json()[0]
    assert entry["profile"] == "old"
    assert "rules" not in entry


def test_history_is_written_atomically(client, monkeypatch):
    seen = []
    monkeypatch.setattr(cfg, "_atomic_write_json",
                        lambda path, data: seen.append((path, data)))
    web_ui.run_history.insert(0, {"timestamp": "x"})
    web_ui.save_history()
    assert seen and seen[0][0] == web_ui.HISTORY_FILE


# --------------------------------------------------------------------------
# profiles: creation (#17), rename (#18), deletion
# --------------------------------------------------------------------------

def _one_device(serial="SER1"):
    def enumerate_mounts():
        return [{"display_name": "Pixel 7", "activation_uri": "mtp://[usb:003,009]/"}]

    def fingerprint(d, verbose=False):
        return ("mtp_serial", serial) if serial else ("", "")

    return enumerate_mounts, fingerprint


def test_create_profile_from_a_connected_device(client, monkeypatch):
    mounts, fingerprint = _one_device()
    monkeypatch.setattr(device, "enumerate_mtp_mounts", mounts)
    monkeypatch.setattr(device, "device_fingerprint", fingerprint)

    resp = client.post("/api/profiles", json={"name": "pixel", "device_id": "SER1"},
                       headers=SAME_ORIGIN)

    assert resp.status_code == 200
    profile = cfg.find_profile(cfg.load_config(), "pixel")
    assert profile["device"]["id_type"] == "mtp_serial"
    assert profile["device"]["id_value"] == "SER1"


def test_create_profile_refuses_a_device_without_a_serial(client, monkeypatch):
    mounts, fingerprint = _one_device(serial="")
    monkeypatch.setattr(device, "enumerate_mtp_mounts", mounts)
    monkeypatch.setattr(device, "device_fingerprint", fingerprint)

    # A serial-less device is still listed, keyed by its activation URI.
    device_id = client.get("/api/device/detect").get_json()[0]["mtp_id"]
    resp = client.post("/api/profiles", json={"name": "pixel", "device_id": device_id},
                       headers=SAME_ORIGIN)

    assert resp.status_code == 400
    assert "serial" in resp.get_json()["error"].lower()
    assert cfg.find_profile(cfg.load_config(), "pixel") is None


def test_create_profile_with_an_unknown_device_is_404(client, monkeypatch):
    mounts, fingerprint = _one_device()
    monkeypatch.setattr(device, "enumerate_mtp_mounts", mounts)
    monkeypatch.setattr(device, "device_fingerprint", fingerprint)

    resp = client.post("/api/profiles", json={"name": "pixel", "device_id": "OTHER"},
                       headers=SAME_ORIGIN)
    assert resp.status_code == 404


def test_create_profile_needs_a_name_and_device(client):
    assert client.post("/api/profiles", json={}, headers=SAME_ORIGIN).status_code == 400


def test_create_profile_rejects_a_non_string_name(client):
    resp = client.post("/api/profiles", json={"name": {"a": 1}, "device_id": "SER1"},
                       headers=SAME_ORIGIN)
    assert resp.status_code == 400


def test_create_profile_rejects_a_non_string_device_id(client):
    resp = client.post("/api/profiles", json={"name": "pixel", "device_id": {"a": 1}},
                       headers=SAME_ORIGIN)
    assert resp.status_code == 400


def test_create_duplicate_profile_is_409(client, monkeypatch):
    mounts, fingerprint = _one_device()
    monkeypatch.setattr(device, "enumerate_mtp_mounts", mounts)
    monkeypatch.setattr(device, "device_fingerprint", fingerprint)
    _seed_profiles("pixel")

    resp = client.post("/api/profiles", json={"name": "pixel", "device_id": "SER1"},
                       headers=SAME_ORIGIN)
    assert resp.status_code == 409


def test_the_dead_device_register_route_is_gone(client):
    assert client.post("/api/device/register", json={"profile_name": "x"},
                       headers=SAME_ORIGIN).status_code == 404


def test_rename_profile(client):
    _seed_profiles("old")
    resp = client.put("/api/profiles/old", json={"name": "new"}, headers=SAME_ORIGIN)

    assert resp.status_code == 200
    config = cfg.load_config()
    assert cfg.find_profile(config, "new") is not None
    assert cfg.find_profile(config, "old") is None


def test_rename_profile_carries_backup_resume_state(client):
    _seed_profiles("old")
    state.save_rule_state("old:r-0001", {"x.jpg"}, {}, 1)

    resp = client.put("/api/profiles/old", json={"name": "new"}, headers=SAME_ORIGIN)

    assert resp.status_code == 200
    assert state.has_resume_state("new:r-0001")


def test_rename_profile_rejects_a_non_string_name(client):
    _seed_profiles("old")
    resp = client.put("/api/profiles/old", json={"name": {"a": 1}}, headers=SAME_ORIGIN)
    assert resp.status_code == 400


def test_rename_unknown_profile_is_404(client):
    assert client.put("/api/profiles/ghost", json={"name": "new"},
                      headers=SAME_ORIGIN).status_code == 404


def test_rename_onto_an_existing_profile_is_409(client):
    _seed_profiles("a", "b")
    assert client.put("/api/profiles/a", json={"name": "b"},
                      headers=SAME_ORIGIN).status_code == 409


def test_rename_to_an_empty_name_is_400(client):
    _seed_profiles("a")
    assert client.put("/api/profiles/a", json={"name": "  "},
                      headers=SAME_ORIGIN).status_code == 400


def test_delete_profile(client):
    _seed_profiles("gone")
    assert client.delete("/api/profiles/gone", headers=SAME_ORIGIN).status_code == 200
    assert cfg.find_profile(cfg.load_config(), "gone") is None


def test_delete_unknown_profile_is_404(client):
    assert client.delete("/api/profiles/ghost", headers=SAME_ORIGIN).status_code == 404


def test_profiles_and_rules_listing(client):
    _seed_profiles("pixel")
    listed = client.get("/api/profiles").get_json()
    assert listed[0]["profile_name"] == "pixel"
    assert client.get("/api/profiles/pixel/rules").get_json()["rules"] == []
    assert client.get("/api/profiles/ghost/rules").status_code == 404


def test_device_detect_uses_the_serial_fingerprint(client, monkeypatch):
    mounts, fingerprint = _one_device()
    monkeypatch.setattr(device, "enumerate_mtp_mounts", mounts)
    monkeypatch.setattr(device, "device_fingerprint", fingerprint)

    body = client.get("/api/device/detect").get_json()
    assert body == [{"device_name": "Pixel 7", "mtp_id": "SER1",
                     "activation_uri": "mtp://[usb:003,009]/", "default_location": ""}]


def test_unregistered_devices_use_the_serial_fingerprint(client, monkeypatch):
    mounts, fingerprint = _one_device()
    monkeypatch.setattr(device, "enumerate_mtp_mounts", mounts)
    monkeypatch.setattr(device, "device_fingerprint", fingerprint)

    body = client.get("/api/device/unregistered").get_json()
    assert body[0]["mtp_id"] == "SER1"
    assert body[0]["id_type"] == "mtp_serial"


# --------------------------------------------------------------------------
# repo rules
# --------------------------------------------------------------------------

def test_web_ui_parses_no_cli_output():
    source = (ROOT / "phone_migration" / "web_ui.py").read_text(encoding="utf-8")
    # Two: the ANSI stripper and the private-use-glyph stripper. Both scrub the
    # log stream for the browser; neither extracts meaning from it.
    assert source.count("re.compile") == 2
    assert "re.search" not in source
    assert "re.match" not in source
    assert "flask_cors" not in source
    assert "CORS(" not in source


def test_flask_cors_is_not_a_requirement():
    text = (ROOT / "requirements-web.txt").read_text(encoding="utf-8")
    assert "flask-cors" not in text
    assert "Flask" in text


def test_debug_is_never_enabled():
    source = (ROOT / "phone_migration" / "web_ui.py").read_text(encoding="utf-8")
    assert "debug=True" not in source


def test_javascript_is_syntactically_valid():
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not on PATH; cannot syntax-check the web UI JavaScript")
    for js in sorted(JS_DIR.glob("*.js")):
        proc = subprocess.run([node, "--check", str(js)], capture_output=True, text=True)
        assert proc.returncode == 0, f"{js.name}: {proc.stderr}"


def test_escape_html_is_safe_in_attribute_context():
    """A phone filename must not be able to break out of a data-* attribute."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not on PATH; cannot exercise the JavaScript escaper")

    main_js = JS_DIR / "main.js"
    script = (f"eval(require('fs').readFileSync({str(main_js)!r}, 'utf8'));"
              "process.stdout.write(escapeHtml('\" onerror=alert(1) x=\"<img>&'));")
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, check=True).stdout

    assert '"' not in out and "<" not in out and ">" not in out
    assert out == "&quot; onerror=alert(1) x=&quot;&lt;img&gt;&amp;"


def test_no_inline_onclick_with_interpolation():
    """Server data must never reach an inline event-handler attribute."""
    offenders = []
    for js in sorted(JS_DIR.glob("*.js")):
        for lineno, line in enumerate(js.read_text(encoding="utf-8").splitlines(), 1):
            if "onclick=" in line and "${" in line:
                offenders.append(f"{js.name}:{lineno}: inline onclick with interpolation")
    assert offenders == []


def test_no_javascript_parses_runner_output():
    """dashboard.js consumed emoji/text sentinels from the CLI log; that is gone."""
    source = (JS_DIR / "dashboard.js").read_text(encoding="utf-8")
    for sentinel in ("[DRY RUN MODE", "Copied:", "Skipped:", "Smart Copy)",
                     "parseOperationLog", "parseAndDisplayOperations"):
        assert sentinel not in source, f"dashboard.js still parses {sentinel!r}"


def test_url_path_parameters_are_encoded():
    """A profile or rule id with a slash must not rewrite the request path."""
    for name in ("profiles.js", "rules.js", "history.js"):
        source = (JS_DIR / name).read_text(encoding="utf-8")
        assert "encodeURIComponent" in source, f"{name} interpolates raw path parameters"


DASHBOARD_DOM_STUB = """
    const nodes = {};
    const make = () => ({
        value: '', innerHTML: '', textContent: '', disabled: false, title: '',
        style: {}, dataset: {},
        addEventListener() {}, removeEventListener() {}, appendChild() {},
        remove() {}, scrollIntoView() {},
        querySelector: () => make(), querySelectorAll: () => [],
        classList: { contains: () => false, add() {}, remove() {} }
    });
    const byId = (id) => (nodes[id] = nodes[id] || make());
    global.document = {
        getElementById: byId, createElement: make, addEventListener() {},
        querySelector: () => null, querySelectorAll: () => [], body: make()
    };
    global.window = { addEventListener() {}, location: { href: '', pathname: '/' } };
    global.sessionStorage = {
        getItem: () => null, setItem() {}, removeItem() {}
    };
    global.setInterval = () => 0;
    global.clearInterval = () => {};
    global.confirm = () => true;
    global.fetch = async () => { throw new Error('offline'); };
"""


def test_dashboard_js_keeps_the_progress_card_after_a_run():
    """The port plan lists the rule-progress card as must-preserve: settling
    its rows and then hiding it in the same tick makes it decorative."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not on PATH; cannot exercise dashboard.js")

    harness = f"""
        const fs = require('fs');
        {DASHBOARD_DOM_STUB}
        eval(fs.readFileSync({str(JS_DIR / 'main.js')!r}, 'utf8'));
        eval(fs.readFileSync({str(JS_DIR / 'dashboard.js')!r}, 'utf8'));
        
        allRules = [{{id: 'r-0001', mode: 'copy', phone_path: '/DCIM',
                     desktop_path: '~/Pictures', manual_only: false}}];
        showOperationProgress('auto');
        const card = document.getElementById('operation-progress-card');
        if (card.style.display !== 'block') throw new Error('card never shown');
        
        applyResultToProgress({{rules: [{{id: 'r-0001', mode: 'copy', stats: {{copied: 2}},
                                        error: null, files: []}}]}});
        resetRunButton();
        if (card.style.display !== 'block') {{
            throw new Error('progress card hidden on completion: ' + card.style.display);
        }}
        if (document.getElementById('operation-status-text').textContent !== 'Finished 1 rule') {{
            throw new Error('rows never settled');
        }}
        process.stdout.write('ok');
    """
    proc = subprocess.run([node, "-e", harness], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "ok"


def test_dashboard_js_escapes_the_selected_rule_ids():
    """buildCommandPreview interpolates server-supplied rule ids into HTML."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not on PATH; cannot exercise dashboard.js")

    harness = f"""
        const fs = require('fs');
        {DASHBOARD_DOM_STUB}
        eval(fs.readFileSync({str(JS_DIR / 'main.js')!r}, 'utf8'));
        eval(fs.readFileSync({str(JS_DIR / 'dashboard.js')!r}, 'utf8'));
        
        const html = buildCommandPreview(true, ['<img onerror=alert(1)>']);
        if (html.includes('<img')) throw new Error('rule id reached innerHTML raw');
        if (!html.includes('&lt;img')) throw new Error('rule id not rendered at all');
        process.stdout.write('ok');
    """
    proc = subprocess.run([node, "-e", harness], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "ok"


def test_dashboard_js_command_preview_is_valid_cli_argv():
    """The CLI has no --dry-run flag (bare --run previews; -y executes) and no
    --rename-duplicates flag (that option is web-only); the previewed command
    must be one the CLI parser actually accepts."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not on PATH; cannot exercise dashboard.js")

    harness = f"""
        const fs = require('fs');
        {DASHBOARD_DOM_STUB}
        eval(fs.readFileSync({str(JS_DIR / 'main.js')!r}, 'utf8'));
        eval(fs.readFileSync({str(JS_DIR / 'dashboard.js')!r}, 'utf8'));

        function commandArgv(html) {{
            const m = html.match(/<div class="command-line">([\\s\\S]*?)<\\/div>/);
            if (!m) throw new Error('no command-line in preview');
            const text = m[1].replace(/<[^>]+>/g, ' ');
            return text.trim().split(/\\s+/);
        }}

        const auto = commandArgv(buildCommandPreview(true));
        const manual = commandArgv(buildCommandPreview(false, ['r-0001', 'r-0002']));
        process.stdout.write(JSON.stringify({{auto, manual}}));
    """
    proc = subprocess.run([node, "-e", harness], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    argvs = json.loads(proc.stdout)

    import main

    for argv in argvs.values():
        assert argv[:2] == ["$", "phone-sync"], argv
        assert "--dry-run" not in argv
        assert "--rename-duplicates" not in argv
        main.build_parser().parse_args(argv[2:])  # must not raise SystemExit

    assert argvs["manual"].count("-r") == 2, argvs["manual"]
    assert "r-0001" in argvs["manual"] and "r-0002" in argvs["manual"]


def test_the_docs_page_matches_what_the_code_does():
    """The in-app docs drifted once; these are the claims that drifted."""
    doc = (ROOT / "phone_migration" / "web_templates" / "documentation.html").read_text(
        encoding="utf-8")

    assert "\u2194" not in doc                  # sync is one-way, desktop -> phone
    assert "Smart Copy" not in doc              # the mode is called Backup
    for claim in ("files that have changed", "haven't changed"):
        assert claim not in doc, f"backup compares name and size, not content: {claim!r}"

    # Bare `--run` previews; anything phrased as executing needs -y.
    for item in doc.split("<li>")[1:]:
        item = item.split("</li>")[0]
        if "--run" in item and "xecute" in item:
            assert "-y" in item, " ".join(item.split())


def test_history_js_renders_pre_run_result_entries():
    """Old history.json entries carry no `rules`/`dry_run`; rendering must not throw."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not on PATH; cannot exercise history.js")

    harness = f"""
        const fs = require('fs');
        const stub = () => ({{
            value: 'all', innerHTML: '', textContent: '', style: {{}},
            addEventListener() {{}}, querySelectorAll() {{ return []; }},
            classList: {{ contains: () => false, add() {{}}, remove() {{}} }}
        }});
        global.document = {{ getElementById: stub, createElement: stub,
                             addEventListener() {{}} }};
        eval(fs.readFileSync({str(JS_DIR / 'main.js')!r}, 'utf8'));
        apiGet = async () => [];          // real escapeHtml, stubbed transport
        showAlert = (m) => {{ throw new Error('unexpected alert: ' + m); }};
        eval(fs.readFileSync({str(JS_DIR / 'history.js')!r}, 'utf8'));
        displayHistory([{{timestamp: '2026-01-01T00:00:00', profile: 'old',
                         rules_count: 2, status: 'success',
                         stats: {{moved: 1}}, logs: ['a line']}}]);
        displayHistory([{{}}]);
        process.stdout.write('ok');
    """
    proc = subprocess.run([node, "-e", harness], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "ok"
