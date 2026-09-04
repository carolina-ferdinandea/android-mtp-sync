"""Interactive phone directory browser."""

from typing import Dict, Any, List
from . import gio_utils, paths
from .theme import Colors, Icons


def _is_root_path(phone_path: str) -> bool:
    return (phone_path or "").strip() in ("", "/")


def list_phone_directory(activation_uri: str, phone_path: str = "/") -> List[Dict[str, Any]]:
    """
    List contents of a phone directory.

    One `gio list` for the whole directory: asking `gio info` per entry meant a
    subprocess per photo, which is minutes of stalling on a camera roll.

    Args:
        activation_uri: MTP activation URI
        phone_path: Path on phone to list

    Returns:
        List of entries with keys name, is_directory, size, path

    Raises:
        gio_utils.GioError: if the listing fails (never reported as empty)
    """
    gio_utils.gio_mount(activation_uri)

    if _is_root_path(phone_path):
        full_uri = activation_uri if activation_uri.endswith("/") else f"{activation_uri}/"
    else:
        full_uri = paths.build_phone_uri(activation_uri, phone_path)
    parent = phone_path.rstrip("/")

    entries = [
        {
            "name": entry["name"],
            "is_directory": entry["is_dir"],
            "size": entry["size"] or 0,
            "path": f"{parent}/{entry['name']}",
        }
        for entry in gio_utils.gio_list_detailed(full_uri)
    ]

    # Directories first, then files, each alphabetically
    entries.sort(key=lambda x: (not x["is_directory"], x["name"].lower()))

    return entries


def browse_phone_interactive(device_info: Dict[str, Any], start_path: str = "/") -> None:
    """
    Interactive browser for phone directories.

    Args:
        device_info: Device info with activation_uri
        start_path: Starting path on phone
    """
    activation_uri = device_info.get("activation_uri", "")
    display_name = device_info.get("display_name", "Phone")

    print(f"\n{Colors.BOLD}{Colors.INFO}{Icons.PHONE} Browsing: {display_name}{Colors.RESET}")
    print(f"{Colors.SEPARATOR}{'=' * 60}{Colors.RESET}")

    # First, show storage roots
    storages = paths.prime_storage_roots(activation_uri)
    print(f"\n{Colors.BOLD}Available Storage:{Colors.RESET}")
    for i, storage in enumerate(storages, 1):
        marker = Colors.SUCCESS if i == 1 else Colors.WARNING
        print(f"  {marker}[{i}]{Colors.RESET} {storage}")
    print(f"  {Colors.ERROR}[0]{Colors.RESET} Cancel")

    try:
        choice = input("\nSelect storage [1]: ").strip() or "1"

        if choice == "0":
            return
        if not choice.isdigit():
            print("Invalid choice")
            return
        idx = int(choice) - 1
        if not (0 <= idx < len(storages)):
            print("Invalid choice")
            return
        storage = storages[idx]

        # Browse from storage root
        browse_path_recursive(activation_uri, f"/{storage}", f"/{storage}")

    except (KeyboardInterrupt, EOFError):
        print("\n\nBrowsing cancelled")


def browse_path_recursive(activation_uri: str, current_path: str, root_path: str) -> None:
    """
    Recursively browse a path on phone.

    Args:
        activation_uri: MTP URI
        current_path: Current path being browsed
        root_path: Selected storage root; "go up" cannot pass this path
    """
    while True:
        print(f"\n{Colors.BOLD}{Colors.PATH}{Icons.FOLDER} {current_path}{Colors.RESET}")
        print(f"{Colors.SEPARATOR}{'-' * 60}{Colors.RESET}")

        try:
            entries = list_phone_directory(activation_uri, current_path)
        except gio_utils.GioError as e:
            print(f"{Colors.ERROR}{Icons.FAIL}{Colors.RESET} Error listing directory: {e}")
            return

        # Show directories first
        dirs = [e for e in entries if e["is_directory"]]
        files = [e for e in entries if not e["is_directory"]]

        if not entries:
            print("  (empty directory)")
        else:
            if dirs:
                print(f"\n{Colors.BOLD}{Colors.INFO}Directories ({len(dirs)}):{Colors.RESET}")
                for i, entry in enumerate(dirs, 1):
                    print(f"  {Colors.SUCCESS}[{i}]{Colors.RESET} {Colors.BOLD}{Icons.FOLDER} {entry['name']}/{Colors.RESET}")

            if files:
                print(f"\n{Colors.DIM}Files ({len(files)}):{Colors.RESET}")
                for entry in files[:10]:  # Show first 10 files
                    size_mb = entry['size'] / (1024 * 1024)
                    if size_mb > 1:
                        size_str = f"{size_mb:.1f} MB"
                    else:
                        size_str = f"{entry['size'] / 1024:.1f} KB"
                    print(f"      {Colors.DIM}{Icons.FILE} {entry['name']} ({size_str}){Colors.RESET}")

                if len(files) > 10:
                    print(f"      {Colors.DIM}... and {len(files) - 10} more files{Colors.RESET}")

        # Menu
        print(f"\n{Colors.BOLD}Options:{Colors.RESET}")
        if dirs:
            print(f"  {Colors.SUCCESS}1-{len(dirs)}{Colors.RESET}: Enter directory")
        print(f"  {Colors.WARNING}[u]{Colors.RESET}: Go up one level")
        print(f"  {Colors.INFO}[c]{Colors.RESET}: Use current path")
        print(f"  {Colors.ERROR}[q]{Colors.RESET}: Quit")

        try:
            choice = input("\nChoice: ").strip().lower()

            if choice == 'q':
                return
            elif choice == 'u':
                # Go up one level
                if current_path.rstrip("/") == root_path.rstrip("/"):
                    print("Already at root")
                else:
                    parts = current_path.rstrip("/").split("/")
                    current_path = "/".join(parts[:-1]) or "/"
            elif choice == 'c':
                print(f"\n{Colors.BOLD}{Colors.SUCCESS}{Icons.OK} Selected path:{Colors.RESET} {Colors.PATH}{current_path}{Colors.RESET}")
                print(f"\n{Colors.BOLD}To use this in a rule:{Colors.RESET}")
                print(f"  {Colors.WARNING}--phone-path{Colors.RESET} {current_path}")
                return
            elif choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(dirs):
                    selected = dirs[idx]
                    new_path = selected['path']
                    if not new_path.startswith("/"):
                        new_path = "/" + new_path
                    current_path = new_path
                else:
                    print("Invalid number")
            else:
                print("Invalid choice")

        except (KeyboardInterrupt, EOFError):
            print("\n\nBrowsing cancelled")
            return


def list_phone_root(device_info: Dict[str, Any]) -> None:
    """
    List root directories on phone (non-interactive).

    Args:
        device_info: Device info with activation_uri
    """
    activation_uri = device_info.get("activation_uri", "")
    display_name = device_info.get("display_name", "Phone")

    print(f"\n{display_name} - Root Directories:\n")
    paths.prime_storage_roots(activation_uri)

    print(f"{Icons.PHONE} Storage roots:")
    try:
        entries = list_phone_directory(activation_uri, "/")
        for entry in entries:
            if entry["is_directory"]:
                print(f"  /{entry['name']}/")
    except gio_utils.GioError as e:
        print(f"  Error: {e}")

    print("\nCommon paths:")
    print("  /DCIM/Camera          - Photos")
    print("  /DCIM/Screenshots     - Screenshots")
    print("  /Download             - Downloads")
    print("  /Movies               - Movies")
    print("  /Music                - Music")
    print("  /Documents            - Documents")
