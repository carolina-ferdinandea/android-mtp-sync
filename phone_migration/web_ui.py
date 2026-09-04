"""Web UI for Phone Migration Tool using Flask.

The API is same-origin only: every request must arrive on a host this server
answers to, and every mutating request must carry a ``Sec-Fetch-Site`` of
``same-origin``/``none`` or an ``Origin`` matching the host. Desktop browsing
and folder creation are confined to ``ALLOWED_ROOTS``.

Run results come from ``runner.run_for_connected_device`` as a structured
``RunResult`` dict; nothing here parses CLI output. The printed lines are
streamed into ``current_run_status["logs"]`` for display only.
"""

import contextlib
import io
import json
import os
import re
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, render_template, jsonify, request

from . import config as cfg, device, runner, browser, rule_validator, state, paths
from .theme import Colors, Icons


app = Flask(__name__,
            template_folder='web_templates',
            static_folder='static',
            static_url_path='/static')

# Disable aggressive caching during development
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Directories the desktop browser may reach into.
ALLOWED_ROOTS = [Path.home(), Path("/media"), Path("/mnt"), Path("/run/media")]

# Methods that cannot change state, and so need no origin check.
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Host header values we answer to. start_web_ui() adds its own host:port.
# A DNS-rebound page is same-origin to its own name, so the origin check alone
# does not stop it - the Host it arrives with does.
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "[::1]"}

# The only two regexes in this module, both scrubbing the log stream for the
# browser: colour codes, and the private-use codepoints theme.Icons picks when
# the server inherits a Nerd-Font terminal's environment (tofu in a browser).
# The trailing \s* closes the gap a removed glyph leaves, keeping indentation.
_ANSI = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
_PRIVATE_USE = re.compile(r'[\ue000-\uf8ff\U000f0000-\U000ffffd]\s*')


def _scrub(line: str) -> str:
    """A printed line, collapsed to its last \\r-overwritten frame and
    stripped of ANSI escapes and private-use glyphs, for the browser and
    history.json alike."""
    return _PRIVATE_USE.sub("", _ANSI.sub("", line.rsplit("\r", 1)[-1])).rstrip()

# Global run state. `result` is the RunResult of the last finished run.
current_run_status = {
    "running": False,
    "progress": 0,
    "logs": [],
    "result": None,
}

# ponytail: one lock for both jobs - they both drive the same phone over the
# same MTP mount, so "one at a time" is the whole requirement. Split it only if
# they ever stop sharing a device.
_run_lock = threading.Lock()


def _busy():
    """True while either a rule run or the test suite holds the device."""
    return current_run_status["running"] or test_run_status["running"]

# History and bookmarks live beside the config, wherever XDG points it.
HISTORY_FILE = cfg.CONFIG_DIR / "history.json"
BOOKMARKS_FILE = cfg.CONFIG_DIR / "bookmarks.json"

# History storage (persisted to disk)
run_history = []

# Bookmarks storage (persisted to disk)
bookmarks = {"desktop": [], "phone": []}

# Validation warnings (updated on device connect)
validation_warnings = []
validation_in_progress = False


@app.before_request
def require_same_origin():
    """Refuse rebound hosts, and cross-site mutating requests."""
    if request.host not in ALLOWED_HOSTS:
        return jsonify({"error": "Bad host"}), 403

    if request.method in SAFE_METHODS:
        return None

    if request.headers.get("Sec-Fetch-Site") in ("same-origin", "none"):
        return None

    origin = urlparse(request.headers.get("Origin", ""))
    if origin.netloc == request.host and origin.scheme == request.scheme:
        return None

    return jsonify({"error": "Cross-origin request refused"}), 403


@app.after_request
def add_no_cache_headers(response):
    response.cache_control.no_cache = True
    response.cache_control.no_store = True
    response.cache_control.must_revalidate = True
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


def _safe_desktop_path(raw_path: str) -> Path:
    """Resolve a user-supplied desktop path, confined to ALLOWED_ROOTS."""
    resolved = Path(os.path.realpath(Path(raw_path).expanduser()))

    if any(resolved.is_relative_to(root) for root in ALLOWED_ROOTS):
        return resolved

    raise PermissionError(f"Path is outside the allowed directories: {resolved}")


def _text(value) -> str:
    """A request field as a stripped string, or "" for anything non-string
    (a JSON object/number/etc.) so it falls through to the existing
    "required" 400s instead of raising in .strip()."""
    return value.strip() if isinstance(value, str) else ""


def _resolve_desktop_path(raw_path: str):
    """Return (path, None), or (None, error_response) for a refused path."""
    try:
        return _safe_desktop_path(raw_path), None
    except (TypeError, ValueError, RuntimeError):    # a JSON object where a path
        return None, (jsonify({"error": "Invalid path"}), 400)  # belongs, embedded
                                                    # NUL, unresolvable ~user
    except PermissionError as e:
        return None, (jsonify({"error": str(e)}), 403)


def _phone_alias_map(activation_uri: str) -> dict:
    return paths.get_storage_alias_map(activation_uri or "")


def _resolve_phone_browser_path(raw_path: str, activation_uri: str) -> str:
    """
    Expand web aliases ("internal/", "sd/") to the device's storage labels.
    """
    phone_path = _text(raw_path) or "/"
    alias_map = _phone_alias_map(activation_uri)

    if phone_path in ("internal", "internal/"):
        return f"/{alias_map.get(paths.DEFAULT_STORAGE_LABEL, paths.DEFAULT_STORAGE_LABEL)}"
    if phone_path.startswith("internal/"):
        suffix = phone_path[len("internal/"):]
        return f"/{alias_map.get(paths.DEFAULT_STORAGE_LABEL, paths.DEFAULT_STORAGE_LABEL)}/{suffix}"

    if phone_path in ("sd", "sd/"):
        return f"/{alias_map.get(paths.SD_STORAGE_LABEL, paths.SD_STORAGE_LABEL)}"
    if phone_path.startswith("sd/"):
        suffix = phone_path[len("sd/"):]
        return f"/{alias_map.get(paths.SD_STORAGE_LABEL, paths.SD_STORAGE_LABEL)}/{suffix}"

    return phone_path


def _bookmark_alias_for_phone_path(phone_path: str, activation_uri: str) -> str:
    """Store bookmarks with stable aliases where possible."""
    path = _text(phone_path)
    if not path:
        return path

    if path.startswith('/storage/emulated/0/'):
        return 'internal/' + path[len('/storage/emulated/0/'):]
    if path.startswith('/storage/'):
        parts = path.split('/', 3)
        if len(parts) >= 3:
            return 'sd/' + (parts[3] if len(parts) > 3 else '')

    alias_map = _phone_alias_map(activation_uri)
    internal = alias_map.get(paths.DEFAULT_STORAGE_LABEL, paths.DEFAULT_STORAGE_LABEL)
    sd = alias_map.get(paths.SD_STORAGE_LABEL, paths.SD_STORAGE_LABEL)

    if path == f"/{internal}":
        return "internal"
    if path.startswith(f"/{internal}/"):
        return "internal/" + path[len(f"/{internal}/"):]

    if path == f"/{sd}":
        return "sd"
    if path.startswith(f"/{sd}/"):
        return "sd/" + path[len(f"/{sd}/"):]

    return path


class StreamingOutput(io.TextIOBase):
    """A stdout stand-in that streams completed, ANSI-stripped lines to a list."""

    def __init__(self, lines):
        self._lines = lines
        self._buffer = ""
        # ponytail: one lock per instance - the spinner thread and the runner
        # thread both write here; upgrade to per-line ordering if that ever matters.
        self._lock = threading.Lock()

    def write(self, text: str) -> int:
        with self._lock:
            self._buffer += text
            while "\n" in self._buffer:
                line, self._buffer = self._buffer.split("\n", 1)
                line = _scrub(line)
                if line.strip():
                    self._lines.append(line)
        return len(text)


def load_history():
    """Load history from disk."""
    global run_history
    try:
        if HISTORY_FILE.exists():
            with open(HISTORY_FILE, 'r') as f:
                run_history = json.load(f)
    except (OSError, ValueError) as e:
        print(f"{Colors.WARNING}{Icons.WARN}{Colors.RESET} Failed to load history: {e}")
        run_history = []


def save_history():
    """Save history to disk."""
    try:
        cfg._atomic_write_json(HISTORY_FILE, run_history)
    except OSError as e:
        print(f"{Colors.WARNING}{Icons.WARN}{Colors.RESET} Failed to save history: {e}")


def load_bookmarks():
    """Load bookmarks from disk."""
    global bookmarks
    try:
        if BOOKMARKS_FILE.exists():
            with open(BOOKMARKS_FILE, 'r') as f:
                loaded = json.load(f)
            bookmarks = {"desktop": loaded.get("desktop", []),
                         "phone": loaded.get("phone", [])}
    except (OSError, ValueError, AttributeError) as e:
        print(f"{Colors.WARNING}{Icons.WARN}{Colors.RESET} Failed to load bookmarks: {e}")
        bookmarks = {"desktop": [], "phone": []}


def save_bookmarks():
    """Save bookmarks to disk."""
    try:
        cfg._atomic_write_json(BOOKMARKS_FILE, bookmarks)
    except OSError as e:
        print(f"{Colors.WARNING}{Icons.WARN}{Colors.RESET} Failed to save bookmarks: {e}")


@app.route('/')
def index():
    """Dashboard page."""
    return render_template('dashboard.html')


@app.route('/profiles')
def profiles():
    """Profiles management page."""
    return render_template('profiles.html')


@app.route('/rules')
def rules():
    """Rules management page."""
    return render_template('rules.html')


@app.route('/history')
def history():
    """History/logs page."""
    return render_template('history.html')


@app.route('/documentation')
def documentation():
    """Documentation page."""
    return render_template('documentation.html')


# === API Routes ===

@app.route('/api/status')
def api_status():
    """Get current system status."""
    global validation_warnings, validation_in_progress
    from . import gio_utils
    config = cfg.load_config()

    # Detect connected device
    profile = runner.detect_connected_device(config, verbose=False)

    if not profile:
        # Clear validation warnings when device disconnected
        validation_warnings = []
        return jsonify({
            "connected": False,
            "accessible": False,
            "device_name": None,
            "profile_name": None,
            "rule_count": 0,
            "validation_warnings": [],
            "validation_in_progress": False
        })

    device_info = profile.get("device", {})
    activation_uri = device_info.get("activation_uri", "")

    # Check device accessibility with a quick check on the device root -
    # faster and more reliable than mounting.
    accessible = False
    if activation_uri:
        try:
            accessible = bool(gio_utils.gio_info(activation_uri, timeout=2))
        except Exception:
            accessible = False

    # Rule validation is wired up end to end but disabled: it can hang for
    # minutes on a slow MTP link. Kept so re-enabling is a one-line change.
    if False and accessible:                    # noqa: SIM223  (deliberate switch)
        def validate_in_background():
            global validation_warnings, validation_in_progress
            try:
                warnings = rule_validator.validate_profile_rules(profile)
                validation_warnings = [w.to_dict() for w in warnings]
            except Exception as e:
                print(f"{Colors.WARNING}{Icons.WARN}{Colors.RESET} "
                      f"Rule validation failed: {e}")
            finally:
                validation_in_progress = False

        if not validation_in_progress:
            validation_in_progress = True
            threading.Thread(target=validate_in_background, daemon=True).start()

    return jsonify({
        "connected": True,
        "accessible": accessible,
        "device_name": device_info.get("display_name", "Unknown"),
        "profile_name": profile.get("name", "unknown"),
        "rule_count": len(profile.get("rules", [])),
        "validation_warnings": validation_warnings,
        "validation_in_progress": validation_in_progress
    })


def _detected_devices():
    """Every connected MTP mount, keyed by its serial fingerprint."""
    found = []
    for d in device.enumerate_mtp_mounts():
        id_type, id_value = device.device_fingerprint(d, verbose=False)
        found.append({
            "device_name": d.get("display_name", "Unknown"),
            "mtp_id": id_value or d.get("activation_uri", ""),
            "activation_uri": d.get("activation_uri", ""),
            "default_location": d.get("default_location", ""),
            "id_type": id_type,
            "id_value": id_value,
        })
    return found


@app.route('/api/profiles', methods=['GET', 'POST'])
def api_profiles():
    """Get all profiles or create a new profile."""
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        profile_name = _text(data.get("name"))
        device_id = _text(data.get("device_id"))

        if not profile_name or not device_id:
            return jsonify({"error": "Profile name and device_id are required"}), 400

        config = cfg.load_config()

        if cfg.find_profile(config, profile_name):
            return jsonify({"error": f"Profile '{profile_name}' already exists"}), 409

        try:
            matching = next((d for d in _detected_devices()
                             if d["mtp_id"] == device_id), None)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

        if not matching:
            return jsonify({"error": "Device not found or not connected"}), 404

        # A device with no serial cannot be recognised again on the next plug-in;
        # storing an empty fingerprint would match every future device.
        if not matching["id_type"] or not matching["id_value"]:
            return jsonify({"error": "Device exposes no serial number; "
                                     "cannot register it reliably"}), 400

        cfg.add_profile(config, {
            "name": profile_name,
            "device": {
                "display_name": matching["device_name"],
                "id_type": matching["id_type"],
                "id_value": matching["id_value"],
                "activation_uri": matching["activation_uri"],
            },
            "rules": []
        })
        cfg.save_config(config)

        return jsonify({"success": True, "message": f"Profile '{profile_name}' created"})

    # GET: Return all profiles
    config = cfg.load_config()
    return jsonify([
        {
            "profile_name": profile.get("name", "unknown"),
            "device_name": profile.get("device", {}).get("display_name", "Unknown"),
            "mtp_id": profile.get("device", {}).get("id_value", "unknown"),
            "rules_count": len(profile.get("rules", []))
        }
        for profile in config.get("profiles", [])
    ])


@app.route('/api/profiles/<profile_name>/rules')
def api_profile_rules(profile_name):
    """Get rules for a specific profile."""
    config = cfg.load_config()
    profile = cfg.find_profile(config, profile_name)

    if not profile:
        return jsonify({"error": "Profile not found"}), 404

    return jsonify({
        "profile": profile_name,
        "rules": profile.get("rules", [])
    })


@app.route('/api/rules', methods=['POST'])
def api_add_rule():
    """Add a new rule."""
    data = request.get_json(silent=True) or {}
    config = cfg.load_config()

    profile_name = _text(data.get("profile"))
    mode = data.get("mode")
    phone_path = data.get("phone_path")
    desktop_path = data.get("desktop_path")
    manual_only = data.get("manual_only", False)

    if not all([profile_name, mode, phone_path, desktop_path]):
        return jsonify({"error": "Missing required fields"}), 400

    # A rule is a path the runner will write to later: confine it like a browse.
    resolved, error = _resolve_desktop_path(desktop_path)
    if error:
        return error
    desktop_path = str(resolved)

    try:
        if mode == "move":
            cfg.add_move_rule(config, profile_name, phone_path, desktop_path, manual_only)
        elif mode == "copy":
            cfg.add_copy_rule(config, profile_name, phone_path, desktop_path, manual_only)
        elif mode in ("backup", "smart_copy"):
            cfg.add_backup_rule(config, profile_name, phone_path, desktop_path, manual_only)
        elif mode == "sync":
            cfg.add_sync_rule(config, profile_name, desktop_path, phone_path, manual_only)
        else:
            return jsonify({"error": f"Invalid mode: {mode}"}), 400

        cfg.save_config(config)
        return jsonify({"success": True, "message": f"{mode.title()} rule added"})

    except (ValueError, KeyError, OSError) as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/rules/<profile_name>/<rule_id>', methods=['DELETE'])
def api_delete_rule(profile_name, rule_id):
    """Delete a rule."""
    config = cfg.load_config()

    try:
        cfg.remove_rule(config, profile_name, rule_id)
        cfg.save_config(config)
        return jsonify({"success": True, "message": "Rule deleted"})
    except (ValueError, KeyError, OSError) as e:
        return jsonify({"error": str(e)}), 500


def _run_worker(dry_run, rule_ids, notify, include_manual, rename_duplicates):
    """Run the rules, streaming printed lines into the status logs."""
    logs = current_run_status["logs"]
    started = datetime.now()
    result = None
    failure = None

    try:
        # ponytail: redirect_stdout is process-global; _run_lock keeps it to one
        # run at a time. Pass a writer into runner if concurrent runs ever land.
        with contextlib.redirect_stdout(StreamingOutput(logs)):
            result = runner.run_for_connected_device(
                cfg.load_config(),
                verbose=True,
                dry_run=dry_run,
                rule_ids=rule_ids,
                notify=notify,
                include_manual=include_manual,
                rename_duplicates=rename_duplicates,
            )
        current_run_status["result"] = result
        current_run_status["progress"] = 100
    except Exception as e:                      # a broken run must still report
        failure = e
        current_run_status["result"] = None
        logs.append(_scrub(f"{Icons.FAIL} Error: {e}"))
    finally:
        # Clear `running` first: a failure below must not wedge every later run
        # behind a permanent 409.
        with _run_lock:
            current_run_status["running"] = False
        try:
            stats = (result or {}).get("stats") or {}
            run_history.insert(0, {
                "timestamp": started.isoformat(),
                "profile": (result or {}).get("profile") or "Unknown",
                "rules_count": len((result or {}).get("rules") or []),
                "status": "error" if failure or stats.get("errors", 0) else "success",
                "dry_run": bool((result or {}).get("dry_run", dry_run)),
                "stats": stats,
                "rules": (result or {}).get("rules") or [],
                "logs": list(logs),
            })
            del run_history[100:]
            save_history()
        except Exception as e:
            print(f"{Colors.WARNING}{Icons.WARN}{Colors.RESET} "
                  f"Failed to record history: {e}")


def _tri_state(value):
    """None means "let each mode keep its own default"; anything else is a bool."""
    return None if value is None else bool(value)


@app.route('/api/run', methods=['POST'])
def api_run():
    """Execute configured rules."""
    data = request.get_json(silent=True) or {}

    with _run_lock:
        if _busy():
            return jsonify({"error": "A run is already in progress"}), 409
        current_run_status["running"] = True
        current_run_status["progress"] = 0
        current_run_status["logs"] = []
        current_run_status["result"] = None

    threading.Thread(
        target=_run_worker,
        args=(data.get("dry_run", False),
              data.get("rule_ids"),
              data.get("notify", False),
              data.get("include_manual", False),
              _tri_state(data.get("rename_duplicates"))),
        daemon=True,
    ).start()

    return jsonify({"success": True, "message": "Run started"})


@app.route('/api/run/status')
def api_run_status():
    """Get current run status: live logs plus the structured result."""
    return jsonify({
        "running": current_run_status["running"],
        "progress": current_run_status["progress"],
        "logs": list(current_run_status["logs"]),
        "result": current_run_status["result"],
    })


@app.route('/api/device/detect')
def api_device_detect():
    """Detect connected MTP devices."""
    return jsonify([
        {
            "device_name": d["device_name"],
            "mtp_id": d["mtp_id"],
            "activation_uri": d["activation_uri"],
            "default_location": d["default_location"],
        }
        for d in _detected_devices()
    ])


@app.route('/api/device/unregistered')
def api_device_unregistered():
    """Detect connected MTP devices that don't have a matching profile."""
    config = cfg.load_config()
    return jsonify([
        d for d in _detected_devices()
        if not cfg.find_profile_by_device_id(config, d["id_type"], d["id_value"])
    ])


@app.route('/api/profiles/<profile_name>', methods=['PUT'])
def api_rename_profile(profile_name):
    """Rename a profile."""
    data = request.get_json(silent=True) or {}
    new_name = _text(data.get("name"))

    if not new_name:
        return jsonify({"error": "A profile name is required"}), 400

    config = cfg.load_config()
    profile = cfg.find_profile(config, profile_name)

    if not profile:
        return jsonify({"error": "Profile not found"}), 404

    if new_name != profile_name and cfg.find_profile(config, new_name):
        return jsonify({"error": f"Profile '{new_name}' already exists"}), 409

    profile["name"] = new_name
    cfg.save_config(config)

    try:
        state.rename_profile(profile_name, new_name)
    except Exception as e:
        print(f"{Colors.WARNING}{Icons.WARN}{Colors.RESET} Failed to carry backup "
              f"resume state to '{new_name}': {e}")

    return jsonify({"success": True, "message": f"Profile renamed to '{new_name}'"})


@app.route('/api/profiles/<profile_name>', methods=['DELETE'])
def api_delete_profile(profile_name):
    """Delete a profile."""
    config = cfg.load_config()

    if not cfg.find_profile(config, profile_name):
        return jsonify({"error": "Profile not found"}), 404

    config["profiles"] = [p for p in config.get("profiles", [])
                          if p.get("name") != profile_name]
    cfg.save_config(config)
    return jsonify({"success": True, "message": "Profile deleted"})


@app.route('/api/history')
def api_history():
    """Get operation history."""
    limit = min(max(request.args.get('limit', 10, type=int), 1), 100)
    return jsonify(run_history[:limit])


@app.route('/api/browse/phone')
def api_browse_phone():
    """Browse phone directories."""
    phone_path = request.args.get('path', '/')

    config = cfg.load_config()
    profile = runner.detect_connected_device(config, verbose=False)

    if not profile:
        return jsonify({"error": "No device connected"}), 409

    activation_uri = profile.get("device", {}).get("activation_uri", "")

    if not activation_uri:
        return jsonify({"error": "Device activation URI not found"}), 500

    phone_path = _resolve_phone_browser_path(phone_path, activation_uri)

    try:
        entries = [
            {
                "name": entry["name"],
                "path": entry["path"],
                "type": "dir" if entry["is_directory"] else "file",
                "size": entry.get("size", 0)
            }
            for entry in browser.list_phone_directory(activation_uri, phone_path)
        ]
        return jsonify({
            "path": phone_path,
            "entries": entries,
            "deviceConnected": True
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/folder/create', methods=['POST'])
def api_create_folder():
    """Create a folder inside an allowed desktop directory."""
    data = request.get_json(silent=True) or {}
    folder_path = data.get('path')

    if not folder_path:
        return jsonify({"error": "Path is required"}), 400

    # The client sends one full path. Traversal segments never belong in it -
    # reject them outright rather than letting realpath quietly absorb them.
    if any(part in ('.', '..') for part in str(folder_path).split('/')):
        return jsonify({"error": "Invalid path"}), 400

    target, error = _resolve_desktop_path(folder_path)
    if error:
        return error

    if target.exists():
        return jsonify({"error": "Folder already exists"}), 409

    try:
        target.mkdir(parents=True)
    except PermissionError:
        return jsonify({"error": "Permission denied"}), 403
    except OSError as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"success": True, "path": str(target)})


@app.route('/api/browse/desktop')
def api_browse_desktop():
    """Browse desktop directories, confined to ALLOWED_ROOTS."""
    resolved, error = _resolve_desktop_path(request.args.get('path') or str(Path.home()))
    if error:
        return error

    if not resolved.exists():
        return jsonify({"error": "Directory not found"}), 404

    if not resolved.is_dir():
        return jsonify({"error": "Path is not a directory"}), 400

    entries = []
    try:
        with os.scandir(resolved) as it:
            for entry in it:
                try:
                    is_symlink = entry.is_symlink()
                    is_dir = entry.is_dir(follow_symlinks=True)
                except OSError:
                    continue
                entries.append({
                    "name": entry.name,
                    "path": entry.path,
                    "type": "dir" if is_dir else "file",
                    "is_symlink": is_symlink
                })
    except PermissionError:
        return jsonify({"error": "Permission denied"}), 403

    entries.sort(key=lambda x: (x["type"] != "dir", x["name"].lower()))

    return jsonify({
        "path": str(resolved),
        "entries": entries,
        "canGoUp": resolved not in ALLOWED_ROOTS
    })


@app.route('/api/bookmarks/<bookmark_type>', methods=['GET'])
def api_get_bookmarks(bookmark_type):
    """Get bookmarks for desktop or phone."""
    if bookmark_type not in ('desktop', 'phone'):
        return jsonify({"error": "Invalid bookmark type. Use 'desktop' or 'phone'"}), 400

    return jsonify({"bookmarks": bookmarks.get(bookmark_type, [])})


@app.route('/api/bookmarks/<bookmark_type>', methods=['POST'])
def api_add_bookmark(bookmark_type):
    """Add a new bookmark."""
    if bookmark_type not in ('desktop', 'phone'):
        return jsonify({"error": "Invalid bookmark type. Use 'desktop' or 'phone'"}), 400

    data = request.get_json(silent=True) or {}
    name = _text(data.get('name'))
    path = _text(data.get('path'))

    if not name or not path:
        return jsonify({"error": "Name and path are required"}), 400

    if bookmark_type == 'desktop':
        # A desktop bookmark is a path the browser will later be pointed at.
        resolved, error = _resolve_desktop_path(path)
        if error:
            return error
        path = str(resolved)
    else:
        profile = runner.detect_connected_device(cfg.load_config(), verbose=False)
        activation_uri = ""
        if profile:
            activation_uri = profile.get("device", {}).get("activation_uri", "")
        path = _bookmark_alias_for_phone_path(path, activation_uri)

    if any(b["path"] == path for b in bookmarks[bookmark_type]):
        return jsonify({"error": "Bookmark already exists"}), 409

    bookmark = {"name": name, "path": path}
    bookmarks[bookmark_type].append(bookmark)
    save_bookmarks()

    return jsonify({"success": True, "bookmark": bookmark})


@app.route('/api/bookmarks/<bookmark_type>/<int:index>', methods=['DELETE'])
def api_delete_bookmark(bookmark_type, index):
    """Delete a bookmark."""
    if bookmark_type not in ('desktop', 'phone'):
        return jsonify({"error": "Invalid bookmark type. Use 'desktop' or 'phone'"}), 400

    if index < 0 or index >= len(bookmarks[bookmark_type]):
        return jsonify({"error": "Invalid bookmark index"}), 404

    removed = bookmarks[bookmark_type].pop(index)
    save_bookmarks()

    return jsonify({"success": True, "removed": removed})


# Test runner state
test_run_status = {
    "running": False,
    "progress": 0,
    "logs": [],
    "results": {"passed": 0, "failed": 0, "skipped": 0},
    "failed_tests": []
}


def _test_worker(test_file, project_root):
    """Stream the edge-case suite's output into test_run_status."""
    out = StreamingOutput(test_run_status["logs"])
    try:
        out.write("Starting edge case test suite...\n")
        out.write(f"Test file: {test_file}\n")

        process = subprocess.Popen(
            [sys.executable, str(test_file)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=str(project_root)
        )

        for line in iter(process.stdout.readline, ''):
            stripped = line.rstrip()
            if not stripped:
                continue
            out.write(stripped + "\n")
            if "PASSED" in stripped:
                test_run_status["results"]["passed"] += 1
            elif "FAILED" in stripped:
                test_run_status["results"]["failed"] += 1
                if "TEST" in stripped:
                    test_run_status["failed_tests"].append(stripped)
            elif "SKIPPED" in stripped:
                test_run_status["results"]["skipped"] += 1

        process.wait()
        out.write("-" * 70 + "\n")
        if process.returncode == 0:
            out.write(f"{Icons.OK} All tests completed successfully\n")
        else:
            out.write(f"{Icons.WARN} Tests completed with exit code "
                      f"{process.returncode}\n")
    except Exception as e:
        out.write(f"{Icons.FAIL} Error: {e}\n")
    finally:
        with _run_lock:
            test_run_status["running"] = False
        test_run_status["progress"] = 100


@app.route('/api/tests/run', methods=['POST'])
def api_run_tests():
    """Run the edge case test suite against the connected device."""
    # Ahead of the device probe: gio must not go poking at a mount a live run
    # is already using. The lock below is still the authoritative check.
    if _busy():
        return jsonify({"error": "A run is already in progress"}), 409

    config = cfg.load_config()
    if not runner.detect_connected_device(config, verbose=False):
        return jsonify({"error": "No device connected. "
                                 "Please connect your phone first."}), 400

    project_root = Path(__file__).parent.parent
    test_file = project_root / "tests" / "test_edge_cases.py"
    if not test_file.exists():
        return jsonify({"error": f"Test file not found: {test_file}"}), 404

    with _run_lock:
        if _busy():
            return jsonify({"error": "A run is already in progress"}), 409
        test_run_status["running"] = True
        test_run_status["progress"] = 0
        test_run_status["logs"] = []
        test_run_status["results"] = {"passed": 0, "failed": 0, "skipped": 0}
        test_run_status["failed_tests"] = []

    threading.Thread(target=_test_worker, args=(test_file, project_root),
                     daemon=True).start()

    return jsonify({"success": True, "message": "Tests started"})


@app.route('/api/tests/status')
def api_test_status():
    """Get current test run status: the worker appends to `logs` as we read."""
    return jsonify({
        "running": test_run_status["running"],
        "progress": test_run_status["progress"],
        "logs": list(test_run_status["logs"]),
        "results": dict(test_run_status["results"]),
        "failed_tests": list(test_run_status["failed_tests"]),
    })


def start_web_ui(host='127.0.0.1', port=8080, debug=False):
    """Start the web UI server (blocking)."""
    ALLOWED_HOSTS.update({f"{host}:{port}", f"localhost:{port}", f"127.0.0.1:{port}"})
    load_history()
    load_bookmarks()

    print(f"\n{Colors.HEADER}{Colors.BOLD}Phone Migration Tool - Web UI{Colors.RESET}")
    print(f"{Colors.SEPARATOR}{'-' * 60}{Colors.RESET}")
    print(f"{Colors.INFO}{Icons.INFO}{Colors.RESET} Server running on "
          f"{Colors.PATH}http://{host}:{port}{Colors.RESET}")
    print("   Open this URL in your browser to access the interface")
    print("   Press Ctrl+C to stop the server\n")

    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == '__main__':
    start_web_ui()
