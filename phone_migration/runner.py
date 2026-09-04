"""Runner: detect the connected device, execute its rules, return a `RunResult`.

`run_for_connected_device` is the single entry point for both the CLI and the
web UI. It returns a structured `RunResult` dict; everything printed to the
terminal is display-only and is derived from that same dict, so no caller ever
has to parse text.

Every real (non-dry-run) execution gets a per-rule preflight disk-space check
first, and, unless `skip_validation` is set, an auto-validation header before
it runs. Progress is shown per rule and overall via `progress.py`. A dry run
that touched at least one rule is analyzed by `dry_run_analyzer` for safety
violations before the run reports itself complete.
"""

from typing import Any, Dict, List, Optional, Tuple

from . import (device, config as cfg, operations, gio_utils, paths, notifications,
               preflight, dry_run_analyzer, progress)
from .theme import Colors, Icons
from .transfer_stats import TransferStats

RULE = "─" * 60

# The ten integer totals in RunResult["stats"]. Per-rule stats keys that appear
# here are summed straight in; everything else (backup's "failed", the "files"
# list) is handled explicitly below.
STAT_KEYS = ("copied", "renamed", "deleted", "errors", "skipped",
             "moved", "synced", "backed_up", "resumed", "folders")

# mode -> the total that counts "files this rule actually transferred"
_TRANSFERRED_AS = {
    "move": "moved",
    "copy": "backed_up",
    "backup": "backed_up",
    "smart_copy": "backed_up",
    "sync": "synced",
}

# mode -> the name of the preflight disk-space check that runs before it
# (skipped entirely in dry-run mode). Looked up via getattr() at call time,
# not bound here, so tests can monkeypatch preflight.preflight_* directly.
_PREFLIGHT_ATTR = {
    "move": "preflight_move",
    "copy": "preflight_copy",
    "backup": "preflight_backup",
    "smart_copy": "preflight_backup",
    "sync": "preflight_sync",
}


def _empty_result(dry_run: bool, profile: Optional[str] = None,
                  device_name: Optional[str] = None) -> Dict[str, Any]:
    """A RunResult with nothing in it - the shape callers can always rely on."""
    return {
        "dry_run": dry_run,
        "profile": profile,
        "device": device_name,
        "stats": {key: 0 for key in STAT_KEYS},
        "transfer": None,
        "rules": [],
    }


def detect_connected_device(config: Dict[str, Any], verbose: bool = False) -> Optional[Dict[str, Any]]:
    """
    Detect a connected MTP device and find its matching profile.

    A device that exposes no serial number fingerprints as ``("", "")``. Such a
    device is skipped rather than looked up, because a hand-edited profile with
    empty id fields would otherwise match every serial-less phone.

    Args:
        config: Configuration dictionary
        verbose: Print verbose output

    Returns:
        The matching profile dict, or None if nothing matched.
    """
    devices = device.enumerate_mtp_mounts()

    if not devices:
        return None

    if verbose:
        print(f"Found {len(devices)} MTP device(s)")

    for dev_info in devices:
        display_name = dev_info.get("display_name", "Unknown")
        id_type, id_value = device.device_fingerprint(dev_info, verbose)

        if verbose:
            print(f"  Checking device: {display_name}")
            print(f"    Fingerprint: {id_type}={id_value}")

        if not id_type or not id_value:
            print(f"{Colors.WARNING}{Icons.WARN}{Colors.RESET} Skipping "
                  f"{Colors.DEVICE_NAME}{display_name}{Colors.RESET}"
                  f"{Colors.DIM}: no serial number to identify it by{Colors.RESET}")
            continue

        profile = cfg.find_profile_by_device_id(config, id_type, id_value)

        if profile:
            if verbose:
                print(f"    {Icons.OK} Matched profile: {profile.get('name', 'unknown')}")

            # The USB port can change between runs; keep the URI current.
            profile["device"]["activation_uri"] = dev_info.get("activation_uri", "")

            return profile

    return None


def _select_rules(all_rules: List[dict], rule_ids: Optional[list],
                  include_manual: bool) -> List[dict]:
    """Rules to run: the named ids, or every rule, or the non-manual ones."""
    if rule_ids:
        return [r for r in all_rules if r.get("id") in rule_ids]
    if include_manual:
        return list(all_rules)
    return [r for r in all_rules if not r.get("manual_only", False)]


def _rename_default(requested: Optional[bool], mode_default: bool) -> bool:
    """An explicit caller wins; None falls back to the mode's own default."""
    return mode_default if requested is None else requested


def _run_one_rule(rule: dict, device_info: dict, profile_name: str, verbose: bool,
                  transfer_tracker: TransferStats,
                  rename_duplicates: Optional[bool]) -> dict:
    """Dispatch one valid rule to its operation. Raises whatever the operation raises.

    `rename_duplicates=None` means "whatever this mode defaults to": move and copy
    rename on a name conflict, backup skips (a backup that renames would duplicate
    the archive on every run).
    """
    mode = rule.get("mode", "unknown")

    if mode == "move":
        return operations.run_move_rule(rule, device_info, verbose, transfer_tracker,
                                        rename_duplicates=_rename_default(rename_duplicates, True))
    if mode == "copy":
        return operations.run_copy_rule(rule, device_info, verbose, transfer_tracker,
                                        rename_duplicates=_rename_default(rename_duplicates, True))
    if mode in ("backup", "smart_copy"):
        return operations.run_backup_rule(rule, device_info, verbose, transfer_tracker,
                                          rename_duplicates=_rename_default(rename_duplicates, False),
                                          profile_name=profile_name)
    if mode == "sync":
        # Sync's source of truth is the desktop, so there is no rename-on-conflict.
        return operations.run_sync_rule(rule, device_info, verbose, transfer_tracker)

    raise AssertionError(f"unhandled mode {mode}")  # guarded by _TRANSFERRED_AS


def _preflight_check(rule: dict, mode: str, device_info: dict) -> Optional[str]:
    """Run this mode's disk-space preflight check before the real operation.

    Returns an error message if the rule must be skipped (not enough space);
    None otherwise. A failure to even *estimate* space (not the check itself)
    is logged and swallowed - a bad estimate must not block a real transfer.
    """
    attr = _PREFLIGHT_ATTR.get(mode)
    if attr is None:
        return None
    check = getattr(preflight, attr)

    print(f"{Colors.DIM}{Icons.INFO} Preflight: checking disk space for "
          f"{mode}...{Colors.RESET}")
    try:
        check(rule, device_info)
    except preflight.PreflightError as e:
        print(f"\n{Colors.ERROR}{Icons.FAIL} Preflight check failed:{Colors.RESET} {e}")
        print(f"{Colors.WARNING}Skipping this rule. Free up space and try again.{Colors.RESET}")
        return str(e)
    except Exception as e:
        print(f"{Colors.WARNING}{Icons.WARN} Preflight check failed:{Colors.RESET} {e}")
        print(f"{Colors.DIM}Continuing anyway...{Colors.RESET}")
    return None


def run_for_connected_device(config: Dict[str, Any], verbose: bool = False,
                             dry_run: bool = False, rule_ids: Optional[list] = None,
                             notify: bool = False, include_manual: bool = False,
                             rename_duplicates: Optional[bool] = None,
                             skip_validation: bool = False) -> Dict[str, Any]:
    """
    Detect the connected device and run its configured rules.

    Args:
        config: Configuration dictionary
        verbose: Print verbose output
        dry_run: Preview actions without changing anything
        rule_ids: Run exactly these rule IDs (manual-only is ignored for them)
        notify: Send a desktop notification on completion
        include_manual: Run every rule, manual-only ones included
        rename_duplicates: On a name conflict, rename instead of skipping.
            None (the default) keeps each mode's own behaviour: move/copy rename,
            backup skips. The web UI passes an explicit bool, which wins for
            every mode.
        skip_validation: Skip the auto-validation header that otherwise precedes
            a real (non-dry-run) execution. For tests.

    Returns:
        A RunResult dict: see the plan's Shared Interfaces. Always a dict, even
        when no device is connected.
    """
    print(f"\n{Colors.SEPARATOR}{RULE}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.HEADER}{Icons.PHONE}  Phone Migration Tool{Colors.RESET}")
    print(f"{Colors.SEPARATOR}{RULE}{Colors.RESET}\n")

    # Auto-validation framing: a real (non-dry-run, non-skipped) execution says
    # so up front. Unconditional: a previous dry run must never leave the
    # gio_utils global set from under a later real run.
    need_validation = not dry_run and not skip_validation
    gio_utils.DRY_RUN = dry_run

    if dry_run:
        print(f"{Colors.BOLD}{Colors.WARNING}{Icons.BOLT} DRY RUN MODE{Colors.RESET} "
              f"{Colors.DIM}(preview only, no changes){Colors.RESET}\n")
    elif need_validation:
        print(f"{Colors.INFO}{Icons.SEARCH} Auto-validating operations before "
              f"execution...{Colors.RESET}\n")

    print(f"{Colors.DIM}{Icons.SEARCH} Scanning for connected devices...{Colors.RESET}")
    profile = detect_connected_device(config, verbose)

    if not profile:
        print(f"\n{Colors.ERROR}{Icons.FAIL} No device found{Colors.RESET}")
        print(f"\n{Colors.BOLD}{Colors.MUTED}Possible reasons:{Colors.RESET}")
        for reason in ("Phone not connected via USB", "File Transfer mode disabled",
                       "Phone is locked", "Device not yet registered"):
            print(f"  {Colors.DIM}{Icons.BULLET}{Colors.RESET} {reason}")

        print(f"\n{Colors.BOLD}{Colors.INFO}Next steps:{Colors.RESET}")
        print(f"  {Colors.ACCENT}1.{Colors.RESET} Connect phone & enable File Transfer")
        print(f"  {Colors.ACCENT}2.{Colors.RESET} Register: "
              f"{Colors.RULE_ID}phone-sync --add-device --name default{Colors.RESET}")
        print(f"  {Colors.ACCENT}3.{Colors.RESET} Execute: "
              f"{Colors.RULE_ID}phone-sync --run -y{Colors.RESET}")

        print(f"\n{Colors.DIM}Debug commands:{Colors.RESET}")
        print(f"  {Colors.MUTED}MTP devices:{Colors.RESET} "
              f"{Colors.DIM}gio mount -li | grep -i mtp{Colors.RESET}")
        print(f"  {Colors.MUTED}Config:{Colors.RESET} "
              f"{Colors.DIM}cat {cfg.CONFIG_FILE} | jq .{Colors.RESET}")

        if notify:
            notifications.notify_device_not_found()

        return _empty_result(dry_run)

    profile_name = profile.get("name", "unknown")
    device_info = profile.get("device", {})
    display_name = device_info.get("display_name", "Unknown")
    result = _empty_result(dry_run, profile_name, display_name)

    print(f"{Colors.SUCCESS}{Icons.OK} Connected:{Colors.RESET} "
          f"{Colors.BOLD}{Colors.DEVICE_NAME}{display_name}{Colors.RESET} "
          f"{Colors.DIM}(profile: {profile_name}){Colors.RESET}")

    activation_uri = device_info.get("activation_uri", "")

    # Device-accessibility probe: list the storage root before running any
    # rule. An empty listing usually means a locked phone; a raised GioError
    # means it could not be reached at all - either way this only warns.
    if activation_uri:
        print(f"{Colors.DIM}{Icons.SEARCH} Verifying access...{Colors.RESET}")
        try:
            paths.prime_storage_roots(activation_uri)
            entries = gio_utils.gio_list(activation_uri if activation_uri.endswith("/")
                                         else f"{activation_uri}/")
            if not entries:  # An empty storage root usually means a locked phone.
                print(f"{Colors.WARNING}{Icons.WARN} Device appears locked{Colors.RESET}")
                print(f"  {Colors.DIM}{Icons.BULLET} Unlock phone and enable "
                      f"File Transfer mode{Colors.RESET}")
            else:
                print(f"{Colors.SUCCESS}{Icons.OK} Access verified{Colors.RESET}")
        except gio_utils.GioError as e:
            if verbose:
                print(f"{Colors.WARNING}{Icons.WARN} Access check failed:{Colors.RESET} "
                      f"{Colors.DIM}{e}{Colors.RESET}")
            print(f"{Colors.DIM}{Icons.BULLET} Ensure phone is unlocked{Colors.RESET}")

    print()

    all_rules = profile.get("rules", [])

    if not all_rules:
        print(f"{Colors.WARNING}{Icons.WARN} No rules configured{Colors.RESET} "
              f"{Colors.DIM}(profile: {profile_name}){Colors.RESET}")
        print(f"\n{Colors.BOLD}{Colors.INFO}Create rules:{Colors.RESET}")
        print(f"  {Colors.RULE_ID}phone-sync --move{Colors.RESET} -p {profile_name} "
              f"-pp {Colors.PATH}/DCIM/Camera{Colors.RESET} -dp {Colors.PATH}~/Pictures{Colors.RESET}")
        print(f"  {Colors.RULE_ID}phone-sync --copy{Colors.RESET} -p {profile_name} "
              f"-pp {Colors.PATH}/DCIM/Camera{Colors.RESET} -dp {Colors.PATH}~/Backup{Colors.RESET}")
        print(f"  {Colors.RULE_ID}phone-sync --sync{Colors.RESET} -p {profile_name} "
              f"-dp {Colors.PATH}~/Videos/motiv{Colors.RESET} -pp {Colors.PATH}/Videos/motiv{Colors.RESET}")
        return result

    rules = _select_rules(all_rules, rule_ids, include_manual)

    if not rules:
        if rule_ids:
            print(f"{Colors.ERROR}{Icons.FAIL} No rules found with the specified IDs: "
                  f"{', '.join(rule_ids)}{Colors.RESET}")
        else:
            print(f"{Colors.WARNING}{Icons.WARN} All {len(all_rules)} rule(s) are "
                  f"marked as [MANUAL]{Colors.RESET}")
            print(f"\n{Colors.DIM}Run them with:{Colors.RESET} "
                  f"{Colors.INFO}--run --manual{Colors.RESET} {Colors.DIM}or{Colors.RESET} "
                  f"{Colors.INFO}--run -r <rule-id>{Colors.RESET}")
        return result

    manual_skipped = 0 if rule_ids else len(all_rules) - len(rules)
    print(f"{Colors.BOLD}Executing {len(rules)} rule(s)...{Colors.RESET}", end="")
    if manual_skipped > 0:
        print(f" {Colors.DIM}({manual_skipped} manual rule(s) skipped){Colors.RESET}")
    else:
        print()
    print(f"{Colors.SEPARATOR}{RULE}{Colors.RESET}")

    if activation_uri:
        gio_utils.gio_mount(activation_uri)

    transfer_tracker = TransferStats()
    transfer_tracker.start()
    totals = result["stats"]
    overall_progress = progress.OperationProgress(len(rules))

    for i, rule in enumerate(rules, 1):
        rule_id = rule.get("id", f"rule-{i}")
        mode = rule.get("mode", "unknown")
        entry = {
            "id": rule_id,
            "mode": mode,
            "phone_path": rule.get("phone_path", ""),
            "desktop_path": rule.get("desktop_path", ""),
            "stats": {},
            "error": None,
            "files": [],
        }
        result["rules"].append(entry)

        if mode not in _TRANSFERRED_AS:
            print(f"\n{Colors.WARNING}{Icons.WARN} Unknown rule mode: {mode} "
                  f"(rule {rule_id}){Colors.RESET}")
            entry["error"] = f"unknown mode {mode}"
            totals["errors"] += 1
            continue

        rule_progress = progress.RuleProgress(rule_id, mode, len(rules), i)
        rule_progress.start()

        if not dry_run:
            preflight_error = _preflight_check(rule, mode, device_info)
            if preflight_error is not None:
                entry["error"] = preflight_error
                totals["errors"] += 1
                rule_progress.stop(success=False, summary=preflight_error)
                overall_progress.update()
                continue

        try:
            stats = _run_one_rule(rule, device_info, profile_name, verbose,
                                  transfer_tracker, rename_duplicates)
        except Exception as e:
            print(f"\n{Colors.ERROR}{Icons.FAIL} Error executing rule "
                  f"{Colors.RULE_ID}{rule_id}{Colors.RESET}: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
            entry["error"] = str(e)
            totals["errors"] += 1
            rule_progress.stop(success=False, summary=str(e))
            overall_progress.update()
            continue

        entry["files"] = stats.get("files", [])
        entry["stats"] = {k: v for k, v in stats.items() if k != "files"}

        for key, value in entry["stats"].items():
            if key in totals:
                totals[key] += value
        # Backup reports copy failures in "failed", not "errors".
        totals["errors"] += entry["stats"].get("failed", 0)
        transferred_as = _TRANSFERRED_AS.get(mode)
        if transferred_as:
            totals[transferred_as] += entry["stats"].get("copied", 0)

        summary = f"{entry['stats'].get('copied', 0)} files"
        if entry["stats"].get("deleted", 0):
            summary += f", {entry['stats']['deleted']} deleted"
        if entry["stats"].get("folders", 0):
            summary += f", {entry['stats']['folders']} folders"
        rule_progress.stop(success=True, summary=summary)
        overall_progress.update()

    transfer_summary = transfer_tracker.get_summary()
    result["transfer"] = {"size_bytes": transfer_summary["size_bytes"],
                          "seconds": float(transfer_summary["time_seconds"])}

    _print_summary(result, transfer_summary)

    if dry_run:
        # A rule that errored has empty stats; the analyzer would read that as
        # "this rule would transfer nothing", which is not what happened.
        rules_stats: List[Tuple[dict, dict]] = [(r, r["stats"]) for r in result["rules"]
                                                if r["error"] is None]
        if rules_stats:
            print(f"\n{Colors.SEPARATOR}{RULE}{Colors.RESET}")
            print(f"\n{Colors.BOLD}{Colors.HEADER}{Icons.SEARCH} "
                  f"Analyzing dry-run results...{Colors.RESET}")

            analysis = dry_run_analyzer.analyze_dry_run_results(rules_stats)
            formatted = dry_run_analyzer.format_analysis_results(analysis)
            if formatted:
                print(formatted)

            if not analysis.is_safe:
                print(f"\n{Colors.ERROR}{Colors.BOLD}{Icons.FAIL} OPERATION BLOCKED{Colors.RESET}")
                print(f"{Colors.ERROR}Critical safety violations detected. "
                      f"Please review the issues above.{Colors.RESET}")
                print(f"\n{Colors.DIM}These issues would cause data loss or "
                      f"inconsistency.{Colors.RESET}")
                return result

            if not analysis.has_warnings and not analysis.info:
                print(f"\n{Colors.SUCCESS}{Colors.BOLD}{Icons.OK} "
                      f"All safety checks passed!{Colors.RESET}")

        print(f"\n{Colors.BOLD}{Colors.WARNING}{Icons.BOLT} DRY RUN{Colors.RESET} "
              f"{Colors.DIM}{Icons.ARROW} no changes made{Colors.RESET}")
        print(f"   {Colors.DIM}Execute with{Colors.RESET} {Colors.SUCCESS}--yes{Colors.RESET} "
              f"{Colors.DIM}or{Colors.RESET} {Colors.SUCCESS}-y{Colors.RESET}")

    if notify:
        notifications.notify_completion(result["stats"], dry_run)

    return result


def _print_summary(result: Dict[str, Any], transfer: Dict[str, Any]) -> None:
    """Render the RunResult totals. Display only - nothing parses this."""
    totals = result["stats"]
    moved = totals["moved"]
    backed_up = totals["backed_up"]
    synced = totals["synced"]
    transferred = moved + backed_up + synced

    print(f"\n{Colors.SEPARATOR}{RULE}{Colors.RESET}")
    print(f"\n{Colors.BOLD}{Colors.HEADER}Results{Colors.RESET}")

    lines = [
        (moved, Colors.MOVED, Icons.MOVE, "Moved from phone", "files"),
        (backed_up, Colors.BACKED_UP, Icons.COPY, "Backed up", "files"),
        (totals["resumed"], Colors.SKIPPED, Icons.SKIP, "Already backed up", "files"),
        (totals["folders"], Colors.ACCENT, Icons.FOLDER, "Folders processed", ""),
        (synced, Colors.SYNCED, Icons.SYNC, "Synced to phone", "files"),
        (totals["renamed"], Colors.RENAMED, Icons.RENAME, "Renamed (conflicts)", ""),
        (totals["skipped"], Colors.SKIPPED, Icons.SKIP, "Skipped (conflict, not copied)", ""),
        (totals["deleted"], Colors.DELETED, Icons.DELETE, "Deleted from phone", ""),
        (totals["errors"], Colors.ERROR, Icons.FAIL, "Errors encountered", ""),
    ]
    for count, color, icon, label, unit in lines:
        if count > 0:
            print(f"  {color}{icon} {label:<32}{Colors.RESET}"
                  f"{Colors.BOLD}{count}{Colors.RESET} {unit}".rstrip())

    if totals["errors"] > 0:
        print(f"\n{Colors.ERROR}{Colors.BOLD}{Icons.FAIL} Completed with errors{Colors.RESET}")
    elif totals["skipped"] > 0 and transferred + totals["renamed"] > 0:
        print(f"\n{Colors.SUCCESS}{Colors.BOLD}{Icons.OK} Completed{Colors.RESET} "
              f"{Colors.DIM}({totals['skipped']} skipped){Colors.RESET}")
    elif transferred + totals["deleted"] > 0:
        print(f"\n{Colors.SUCCESS}{Colors.BOLD}{Icons.OK} All operations successful{Colors.RESET}")
    else:
        print(f"\n{Colors.INFO}{Icons.INFO} Already in sync{Colors.RESET}")

    if transferred > 0 and transfer["size_bytes"] > 0:
        print(f"\n  {Colors.MUTED}Transfer{Colors.RESET} {Colors.DIM}|{Colors.RESET} "
              f"{transfer['size']} {Colors.DIM}in{Colors.RESET} {transfer['time']}")
        if transfer["speed_mbps"] > 0.1:
            print(f"  {Colors.MUTED}Speed{Colors.RESET}    {Colors.DIM}|{Colors.RESET} "
                  f"{Colors.ACCENT}{transfer['speed']}{Colors.RESET}")
