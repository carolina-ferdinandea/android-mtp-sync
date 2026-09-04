"""Tests for phone_migration.paths."""

from pathlib import Path

import pytest

from phone_migration import paths


# --- storage root discovery ---------------------------------------------------

def test_get_storage_roots_falls_back_when_query_fails(monkeypatch):
    monkeypatch.setattr(paths.gio_utils, "gio_mount", lambda uri: None)
    monkeypatch.setattr(paths.gio_utils, "gio_list",
                        lambda uri: (_ for _ in ()).throw(paths.gio_utils.GioError("boom")))
    paths._ROOTS_CACHE.clear()

    assert paths.prime_storage_roots("mtp://phone/") == ["Internal storage", "SD Card"]


def test_get_storage_roots_uses_gio_results(monkeypatch):
    monkeypatch.setattr(paths.gio_utils, "gio_mount", lambda uri: None)
    monkeypatch.setattr(paths.gio_utils, "gio_list",
                        lambda uri: ["Interner gemeinsamer Speicher", "1234-5678"])
    paths._ROOTS_CACHE.clear()

    assert paths.prime_storage_roots("mtp://phone/") == [
        "Interner gemeinsamer Speicher",
        "1234-5678",
    ]


# --- expand_desktop ---------------------------------------------------------

@pytest.mark.parametrize("empty", ["", "   ", "\t\n"])
def test_expand_desktop_rejects_an_empty_path(empty):
    """An empty desktop_path used to resolve to the CWD and get mirrored."""
    with pytest.raises(ValueError, match="desktop_path is empty"):
        paths.expand_desktop(empty)


def test_expand_desktop_expands_tilde():
    assert paths.expand_desktop("~/Pictures") == (Path.home() / "Pictures").resolve()


def test_expand_desktop_expands_env_vars(monkeypatch, tmp_path):
    monkeypatch.setenv("PM_TEST_DIR", str(tmp_path))
    assert paths.expand_desktop("$PM_TEST_DIR/shots") == (tmp_path / "shots").resolve()


# --- normalize_phone_path ---------------------------------------------------

@pytest.mark.parametrize("phone_path, expected", [
    ("/DCIM/Camera", ("Internal storage", ["DCIM", "Camera"])),
    ("DCIM/Camera", ("Internal storage", ["DCIM", "Camera"])),
    ("DCIM\\Camera", ("Internal storage", ["DCIM", "Camera"])),
    ("~/is/DCIM", ("Internal storage", ["DCIM"])),
    ("~/sd/Music", ("SD Card", ["Music"])),
    ("Internal storage/DCIM", ("Internal storage", ["DCIM"])),
    ("SD Card/Music", ("SD Card", ["Music"])),
    ("/", ("Internal storage", [])),
    ("", ("Internal storage", [])),
])
def test_normalize_phone_path(phone_path, expected):
    assert paths.normalize_phone_path(phone_path) == expected


@pytest.mark.parametrize("bare_label", ["Internal storage", "SD Card", "Internal storage/"])
def test_normalize_phone_path_accepts_a_bare_storage_label(bare_label):
    """Without a separator-aware match the label was kept as a path segment,
    building `.../Internal storage/Internal storage`."""
    label, segments = paths.normalize_phone_path(bare_label)
    assert label == bare_label.rstrip("/")
    assert segments == []


def test_normalize_phone_path_does_not_match_a_label_prefix():
    assert paths.normalize_phone_path("Internal storageX/DCIM") == (
        "Internal storage", ["Internal storageX", "DCIM"],
    )


@pytest.mark.parametrize("traversal", [
    "/../../etc",
    "/DCIM/../../../etc",
    "/DCIM/./Camera/..",
    "..",
])
def test_normalize_phone_path_drops_dot_segments(traversal):
    """Finding #12: `..` segments escaped the storage prefix via the web UI."""
    _, segments = paths.normalize_phone_path(traversal)
    assert "." not in segments
    assert ".." not in segments


def test_normalize_phone_path_keeps_the_surviving_segments():
    assert paths.normalize_phone_path("/DCIM/../Camera/./shot.jpg") == (
        "Internal storage", ["DCIM", "Camera", "shot.jpg"],
    )


def test_normalize_phone_path_drops_empty_segments():
    assert paths.normalize_phone_path("//DCIM///Camera//") == (
        "Internal storage", ["DCIM", "Camera"],
    )


# --- build_phone_uri --------------------------------------------------------

def test_build_phone_uri_quotes_the_storage_label():
    assert paths.build_phone_uri("mtp://[usb:003,009]/", "/DCIM") == (
        "mtp://[usb:003,009]/Internal%20storage/DCIM"
    )


def test_build_phone_uri_quotes_every_segment():
    assert paths.build_phone_uri("mtp://x/", "/a b#c/100%.jpg") == (
        "mtp://x/Internal%20storage/a%20b%23c/100%25.jpg"
    )


def test_build_phone_uri_adds_the_trailing_slash_to_the_activation_uri():
    assert paths.build_phone_uri("mtp://x", "/DCIM") == "mtp://x/Internal%20storage/DCIM"


def test_build_phone_uri_cannot_escape_the_storage_prefix():
    assert paths.build_phone_uri("mtp://x/", "/../../etc") == "mtp://x/Internal%20storage/etc"


def test_build_phone_uri_maps_internal_label_to_localized_storage(monkeypatch):
    monkeypatch.setattr(paths.gio_utils, "gio_mount", lambda uri: None)
    monkeypatch.setattr(paths.gio_utils, "gio_list",
                        lambda uri: ["Interner gemeinsamer Speicher", "1234-5678"])
    paths._ROOTS_CACHE.clear()
    paths.prime_storage_roots("mtp://sony/")

    assert paths.build_phone_uri("mtp://sony/", "/DCIM/Camera") == (
        "mtp://sony/Interner%20gemeinsamer%20Speicher/DCIM/Camera"
    )


def test_build_phone_uri_accepts_explicit_localized_storage_labels(monkeypatch):
    monkeypatch.setattr(paths.gio_utils, "gio_mount", lambda uri: None)
    monkeypatch.setattr(paths.gio_utils, "gio_list",
                        lambda uri: ["Interner gemeinsamer Speicher"])
    paths._ROOTS_CACHE.clear()
    paths.prime_storage_roots("mtp://sony/")

    assert paths.build_phone_uri("mtp://sony/", "/Interner gemeinsamer Speicher/DCIM") == (
        "mtp://sony/Interner%20gemeinsamer%20Speicher/DCIM"
    )


# --- next_available_name ----------------------------------------------------

def test_next_available_name_returns_the_plain_path_when_free(tmp_path):
    assert paths.next_available_name(tmp_path, "photo.jpg") == tmp_path / "photo.jpg"


def test_next_available_name_appends_a_counter(tmp_path):
    (tmp_path / "photo.jpg").touch()
    assert paths.next_available_name(tmp_path, "photo.jpg") == tmp_path / "photo (1).jpg"

    (tmp_path / "photo (1).jpg").touch()
    assert paths.next_available_name(tmp_path, "photo.jpg") == tmp_path / "photo (2).jpg"


def test_next_available_name_returns_none_when_renaming_is_off(tmp_path):
    (tmp_path / "photo.jpg").touch()
    assert paths.next_available_name(tmp_path, "photo.jpg", rename_duplicates=False) is None


@pytest.mark.parametrize("name, renamed", [
    (".bashrc", ".bashrc (1)"),          # leading dot is the stem, not an extension
    ("README", "README (1)"),
    ("archive.tar.gz", "archive.tar (1).gz"),
])
def test_next_available_name_splits_on_the_real_suffix(tmp_path, name, renamed):
    (tmp_path / name).touch()
    assert paths.next_available_name(tmp_path, name) == tmp_path / renamed


def test_next_available_name_gives_up_after_1000_candidates(tmp_path):
    """Used to raise RuntimeError and abort the whole run."""
    (tmp_path / "x.txt").touch()
    for i in range(1, 1001):
        (tmp_path / f"x ({i}).txt").touch()
    assert paths.next_available_name(tmp_path, "x.txt") is None
