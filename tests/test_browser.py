"""Tests for phone_migration.browser.list_phone_directory.

One `gio list -a ...` per directory, never one `gio info` per entry: a camera
roll with 5k photos used to mean 5k subprocesses inside a single web request.
"""

import pytest

from phone_migration import browser, gio_utils, paths, theme


LISTING = [
    {"name": "b.jpg", "is_dir": False, "size": 2048},
    {"name": "Camera", "is_dir": True, "size": None},
    {"name": "A.mp4", "is_dir": False, "size": None},
]


@pytest.fixture
def gio(monkeypatch):
    """Record gio traffic; gio_info is a trap - the browser must not call it."""
    calls = {"list": [], "mount": []}

    def fake_list(uri):
        calls["list"].append(uri)
        return list(LISTING)

    def trap(*args, **kwargs):
        raise AssertionError("list_phone_directory called gio info per entry")

    monkeypatch.setattr(gio_utils, "gio_list_detailed", fake_list)
    monkeypatch.setattr(gio_utils, "gio_mount", lambda uri: calls["mount"].append(uri))
    monkeypatch.setattr(gio_utils, "gio_info", trap)
    monkeypatch.setattr(gio_utils, "gio_list", trap)
    return calls


def test_one_listing_call_for_the_whole_directory(gio):
    browser.list_phone_directory("mtp://phone/", "/DCIM")

    assert gio["list"] == [paths.build_phone_uri("mtp://phone/", "/DCIM")]


def test_device_is_mounted_first(gio):
    browser.list_phone_directory("mtp://phone/", "/DCIM")

    assert gio["mount"] == ["mtp://phone/"]


def test_directories_sort_first_then_names_case_insensitively(gio):
    entries = browser.list_phone_directory("mtp://phone/", "/DCIM")

    assert [e["name"] for e in entries] == ["Camera", "A.mp4", "b.jpg"]


def test_entry_shape_matches_what_callers_read(gio):
    entries = browser.list_phone_directory("mtp://phone/", "/DCIM")

    assert entries[0] == {
        "name": "Camera",
        "is_directory": True,
        "size": 0,
        "path": "/DCIM/Camera",
    }
    assert entries[2] == {
        "name": "b.jpg",
        "is_directory": False,
        "size": 2048,
        "path": "/DCIM/b.jpg",
    }


def test_root_paths_do_not_double_their_slash(gio):
    entries = browser.list_phone_directory("mtp://phone/", "/")

    assert entries[0]["path"] == "/Camera"


def test_root_listing_uses_the_activation_uri(gio):
    browser.list_phone_directory("mtp://phone/", "/")

    assert gio["list"] == ["mtp://phone/"]


def test_storage_prefixed_paths_do_not_double_their_slash(gio):
    entries = browser.list_phone_directory("mtp://phone/", "SD Card/")

    assert entries[0]["path"] == "SD Card/Camera"


def test_a_failed_listing_is_not_an_empty_directory(monkeypatch):
    def boom(uri):
        raise gio_utils.GioError("Failed to open file: device is busy")

    monkeypatch.setattr(gio_utils, "gio_list_detailed", boom)
    monkeypatch.setattr(gio_utils, "gio_mount", lambda uri: None)

    with pytest.raises(gio_utils.GioError):
        browser.list_phone_directory("mtp://phone/", "/DCIM")


def test_browser_has_no_palette_of_its_own():
    assert browser.Colors is theme.Colors
