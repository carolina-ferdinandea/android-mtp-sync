"""Path manipulation utilities for desktop and phone paths."""

import os
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

from . import gio_utils


DEFAULT_STORAGE_LABEL = "Internal storage"
SD_STORAGE_LABEL = "SD Card"

# Storage labels a phone path may name explicitly, and the "~/is", "~/sd" shortcuts.
STORAGE_LABELS = (DEFAULT_STORAGE_LABEL, SD_STORAGE_LABEL)
STORAGE_SHORTCUTS = {"is": DEFAULT_STORAGE_LABEL, "sd": SD_STORAGE_LABEL}

_ROOTS_CACHE: Dict[str, Tuple[str, ...]] = {}

# Highest " (n)" suffix tried before a copy is given up on.
# ponytail: 1000 is plenty for a camera roll; raise it if a real collection hits it.
MAX_DUPLICATES = 1000


def expand_desktop(path_str: str) -> Path:
    """
    Expand desktop path with tilde and environment variables.

    Args:
        path_str: Path string potentially with ~ or $VAR

    Returns:
        Absolute Path object

    Raises:
        ValueError: if the path is empty — Path("").resolve() is the CWD, and a
            rule silently pointed at the CWD mirrors or deletes the wrong tree.
    """
    if not (path_str or "").strip():
        raise ValueError("desktop_path is empty")

    expanded = os.path.expanduser(os.path.expandvars(path_str.strip()))
    return Path(expanded).resolve()


def ensure_dir(path: Path) -> None:
    """
    Create directory and parents if they don't exist.

    Args:
        path: Path object to create
    """
    path.mkdir(parents=True, exist_ok=True)


def _uri_with_trailing_slash(uri: str) -> str:
    return uri if uri.endswith("/") else f"{uri}/"


def get_storage_roots(activation_uri: str, refresh: bool = False) -> List[str]:
    """
    List storage-root labels available on the connected phone.

    Falls back to the built-in labels when the phone cannot be queried.
    """
    if not activation_uri.startswith("mtp://"):
        return list(STORAGE_LABELS)

    uri = _uri_with_trailing_slash(activation_uri)
    if not refresh and uri in _ROOTS_CACHE:
        return list(_ROOTS_CACHE[uri])

    try:
        gio_utils.gio_mount(uri)
        roots = [name.rstrip("/") for name in gio_utils.gio_list(uri) if name.strip()]
    except gio_utils.GioError:
        roots = []

    if not roots:
        roots = list(STORAGE_LABELS)

    deduped = tuple(dict.fromkeys(roots))
    _ROOTS_CACHE[uri] = deduped
    return list(deduped)


def _pick_internal_storage_label(roots: List[str]) -> str:
    if DEFAULT_STORAGE_LABEL in roots:
        return DEFAULT_STORAGE_LABEL

    candidates = []
    for root in roots:
        lower = root.casefold()
        looks_sd = "sd" in lower or "card" in lower or "-" in root
        if not looks_sd:
            candidates.append(root)

    if candidates:
        return candidates[0]
    return roots[0] if roots else DEFAULT_STORAGE_LABEL


def _pick_sd_storage_label(roots: List[str], internal_label: str) -> Optional[str]:
    if SD_STORAGE_LABEL in roots:
        return SD_STORAGE_LABEL

    others = [r for r in roots if r != internal_label]
    for root in others:
        lower = root.casefold()
        if "sd" in lower or "card" in lower or "-" in root:
            return root
    return others[0] if others else None


def get_storage_alias_map(activation_uri: str) -> Dict[str, str]:
    """
    Map logical labels used in rules to localized device labels.
    """
    roots = get_storage_roots(activation_uri)
    internal = _pick_internal_storage_label(roots)
    mapping = {DEFAULT_STORAGE_LABEL: internal}

    sd = _pick_sd_storage_label(roots, internal)
    if sd:
        mapping[SD_STORAGE_LABEL] = sd

    return mapping


def normalize_phone_path(phone_path: str,
                         storage_labels: Optional[Iterable[str]] = None) -> Tuple[str, List[str]]:
    """
    Normalize phone path and extract storage label and segments.

    Args:
        phone_path: Path on phone, supports shortcuts:
            - "/path" or "~/is/path" -> Internal storage (default)
            - "~/sd/path" -> SD Card storage
            - "Internal storage/path" -> Explicit internal storage
            - "SD Card/path" -> Explicit SD card

    Returns:
        Tuple of (storage_label, path_segments). "." and ".." are dropped, so
        the result can never climb above the storage root.
    """
    # Split on both separators first, so a storage label is only recognised as a
    # whole segment ("Internal storage" alone is the label; "Internal storageX"
    # is an ordinary directory).
    segments = [s for s in (phone_path or "").strip().replace("\\", "/").split("/")
                if s and s not in (".", "..")]

    labels = tuple(storage_labels) if storage_labels is not None else STORAGE_LABELS

    if len(segments) >= 2 and segments[0] == "~" and segments[1] in STORAGE_SHORTCUTS:
        return STORAGE_SHORTCUTS[segments[1]], segments[2:]

    if segments and segments[0] in labels:
        return segments[0], segments[1:]

    return DEFAULT_STORAGE_LABEL, segments


def build_phone_uri(activation_uri: str, phone_path: str) -> str:
    """
    Build full MTP URI for a phone path.

    Args:
        activation_uri: Base MTP URI (e.g., "mtp://[usb:003,009]/")
        phone_path: Path on phone (e.g., "/DCIM/Camera")

    Returns:
        Full MTP URI (e.g., "mtp://[usb:003,009]/Internal%20storage/DCIM/Camera")
    """
    activation_uri = _uri_with_trailing_slash(activation_uri)
    roots = get_storage_roots(activation_uri)
    alias_map = get_storage_alias_map(activation_uri)

    known_labels = tuple(dict.fromkeys((*STORAGE_LABELS, *roots)))
    storage_label, segments = normalize_phone_path(phone_path, storage_labels=known_labels)
    storage_label = alias_map.get(storage_label, storage_label)

    # The storage label holds a space, so it needs encoding just like the rest.
    return activation_uri + "/".join(quote(s, safe='') for s in [storage_label] + segments)


def next_available_name(dest_dir: Path, base_name: str,
                        rename_duplicates: bool = True) -> Optional[Path]:
    """
    Find next available filename by appending (1), (2), etc.

    Args:
        dest_dir: Destination directory
        base_name: Original filename
        rename_duplicates: If True, rename on conflict; if False, skip on conflict

    Returns:
        Available Path (original or with a " (n)" suffix), or None when the name
        is taken and no free variant was found within MAX_DUPLICATES.
    """
    dest_path = dest_dir / base_name
    if not dest_path.exists():
        return dest_path

    if not rename_duplicates:
        return None

    # Path.suffix keeps a leading dot with the stem, so ".bashrc" -> ".bashrc (1)".
    stem, suffix = dest_path.stem, dest_path.suffix

    for counter in range(1, MAX_DUPLICATES + 1):
        candidate = dest_dir / f"{stem} ({counter}){suffix}"
        if not candidate.exists():
            return candidate

    return None
