"""
M.C.O (Mini Command Operator) - Web Terminal Backend
Flask application implementing a whitelisted, sandboxed command interpreter.

Security notes:
- No eval()/exec().
- No os.system().
- No subprocess call ever receives shell=True.
- No subprocess call ever receives raw, unvalidated user input.
- RUN never executes remote code; it only inspects a GitHub repo reference.
- All file access for DATA commands is restricted to the local data/ directory.
- All network checks are validated, timeout-bound, and output-limited.
"""

import base64
import hashlib
import ipaddress
import json
import os
import re
import shlex
import socket
import ssl
import subprocess
import time
from datetime import datetime

from flask import Flask, render_template, request, jsonify, session

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

APP_VERSION = "M.C.O v0.1"
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

app = Flask(__name__)
app.secret_key = os.environ.get("MCO_SECRET_KEY", "mco-dev-secret-change-me")

START_TIME = time.time()

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")

COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 8080]
MAX_PORTS_CHECKED = 10


def is_valid_target(value: str) -> bool:
    """Accept only a plain hostname or a valid IPv4/IPv6 address."""
    if not value or len(value) > 253:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    return bool(HOSTNAME_RE.match(value))


def is_safe_filename(name: str) -> bool:
    return bool(SAFE_FILENAME_RE.match(name)) and ".." not in name


def resolve_alias(value: str) -> str:
    aliases = session.get("aliases", {})
    return aliases.get(value, value)


def get_target(explicit: str = None) -> str:
    if explicit:
        return resolve_alias(explicit)
    return session.get("target")


# ---------------------------------------------------------------------------
# CORE commands
# ---------------------------------------------------------------------------

HELP_TEXT = """[CORE]
help
clear
history
version
about
exit

[RUN]
run "user/project"

[CHECK]
check ping target
check dns target
check ip target
check ports target
check http target
check headers target
check cert target
check trace target
check route target
check whois target

[TARGET]
target 192.168.1.20

[ALIAS]
alias name = value

[DATA]
hash sha256 "text"
encode base64 "text"
decode base64 "text"
json filename.json
search "term" filename.txt

[SYSTEM]
system
cpu
memory
disk
process
uptime"""


def cmd_help(_args):
    return ok(HELP_TEXT)


def cmd_version(_args):
    return ok(APP_VERSION)


def cmd_about(_args):
    return ok(
        "M.C.O - Mini Command Operator\n"
        "A lightweight, sandboxed diagnostics terminal for hosts and labs "
        "you have permission to inspect. No arbitrary shell execution."
    )


def cmd_history(_args):
    return ok("History is tracked client-side in this session.")


def cmd_clear(_args):
    return ok("__CLEAR__")


def cmd_exit(_args):
    return ok("Session ended (client-side). Refresh to start a new session.")


# ---------------------------------------------------------------------------
# TARGET / ALIAS
# ---------------------------------------------------------------------------

def cmd_target(args):
    if not args:
        current = session.get("target")
        return ok(f"Current target: {current}" if current else "No target selected.")
    value = resolve_alias(args[0])
    if not is_valid_target(value):
        return err(f"Invalid target: {args[0]}")
    session["target"] = value
    session.modified = True
    return ok(f"Target set: {value}")


def cmd_alias(args):
    # syntax: alias name = value
    if len(args) < 3 or args[1] != "=":
        return err('Usage: alias name = value')
    name, value = args[0], args[2]
    if not is_safe_filename(name):
        return err("Invalid alias name.")
    aliases = session.get("aliases", {})
    aliases[name] = value
    session["aliases"] = aliases
    session.modified = True
    return ok(f"Alias created: {name} -> {value}")


# ---------------------------------------------------------------------------
# CHECK commands
# ---------------------------------------------------------------------------

def _target_or_error(args):
    target = get_target(args[0] if args else None)
    if not target:
        return None, err("No target selected.")
    if not is_valid_target(target):
        return None, err(f"Invalid target: {target}")
    return target, None


def check_ping(args):
    target, error = _target_or_error(args)
    if error:
        return error
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", target],
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = (result.stdout or result.stderr).strip()
        output = "\n".join(output.splitlines()[:10])
        return ok(output if output else "No response.")
    except subprocess.TimeoutExpired:
        return err(f"Ping to {target} timed out.")
    except FileNotFoundError:
        return err("ping utility not available in this environment.")
    except Exception as e:
        return err(f"Ping failed: {e}")


def check_dns(args):
    target, error = _target_or_error(args)
    if error:
        return error
    try:
        host, aliaslist, addrlist = socket.gethostbyname_ex(target)
        lines = [f"Host      : {host}"]
        if aliaslist:
            lines.append(f"Aliases   : {', '.join(aliaslist)}")
        lines.append(f"Addresses : {', '.join(addrlist)}")
        return ok("\n".join(lines))
    except socket.gaierror as e:
        return err(f"DNS lookup failed: {e}")
    except Exception as e:
        return err(f"DNS lookup failed: {e}")


def check_ip(args):
    target, error = _target_or_error(args)
    if error:
        return error
    try:
        ip = socket.gethostbyname(target)
        return ok(f"{target} -> {ip}")
    except socket.gaierror as e:
        return err(f"Could not resolve {target}: {e}")


def check_ports(args):
    target, error = _target_or_error(args)
    if error:
        return error
    ports = COMMON_PORTS[:MAX_PORTS_CHECKED]
    lines = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target, port))
                state = "OPEN" if result == 0 else "closed"
                lines.append(f"{port:<6} {state}")
        except socket.gaierror as e:
            return err(f"Could not resolve {target}: {e}")
        except Exception as e:
            lines.append(f"{port:<6} error: {e}")
    return ok(f"Ports scanned for {target} (common ports only):\n" + "\n".join(lines))


def _normalize_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"https://{target}"


def check_http(args):
    target, error = _target_or_error(args)
    if error:
        return error
    if requests is None:
        return err("HTTP check unavailable: requests library not installed.")
    url = _normalize_url(target)
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True)
        return ok(
            f"URL         : {url}\n"
            f"Status Code : {resp.status_code}\n"
            f"Final URL   : {resp.url}\n"
            f"Elapsed     : {resp.elapsed.total_seconds():.3f}s\n"
            f"Body Size   : {len(resp.content)} bytes"
        )
    except requests.exceptions.RequestException as e:
        return err(f"HTTP check failed: {e}")


def check_headers(args):
    target, error = _target_or_error(args)
    if error:
        return error
    if requests is None:
        return err("Headers check unavailable: requests library not installed.")
    url = _normalize_url(target)
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True)
        lines = [f"{k}: {v}" for k, v in list(resp.headers.items())[:25]]
        return ok("\n".join(lines) if lines else "No headers returned.")
    except requests.exceptions.RequestException as e:
        return err(f"Headers check failed: {e}")


def check_cert(args):
    target, error = _target_or_error(args)
    if error:
        return error
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return ok(
            f"Host       : {host}\n"
            f"Subject CN : {subject.get('commonName', 'n/a')}\n"
            f"Issuer     : {issuer.get('commonName', 'n/a')}\n"
            f"Valid From : {cert.get('notBefore')}\n"
            f"Valid To   : {cert.get('notAfter')}"
        )
    except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
        return err(f"Certificate check failed: {e}")
    except ssl.SSLError as e:
        return err(f"TLS handshake failed: {e}")
    except Exception as e:
        return err(f"Certificate check failed: {e}")


def check_trace(args):
    target, error = _target_or_error(args)
    if error:
        return error
    return ok(
        f"Traceroute to {target} is not available in this hosted environment "
        "(raw sockets / ICMP are typically restricted on PaaS platforms)."
    )


def check_route(args):
    target, error = _target_or_error(args)
    if error:
        return error
    return ok("Route information is not available in this hosted environment.")


def _whois_query(server: str, query: str, timeout: float = 5.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode(errors="replace")


def check_whois(args):
    target, error = _target_or_error(args)
    if error:
        return error
    try:
        response = _whois_query("whois.iana.org", target)
        referral = None
        for line in response.splitlines():
            if line.lower().startswith("whois:"):
                referral = line.split(":", 1)[1].strip()
                break
        if referral:
            response = _whois_query(referral, target)
        lines = response.strip().splitlines()[:30]
        return ok("\n".join(lines) if lines else "No whois data returned.")
    except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
        return err(f"Whois lookup failed: {e}")
    except Exception as e:
        return err(f"Whois lookup failed: {e}")


CHECK_HANDLERS = {
    "ping": check_ping,
    "dns": check_dns,
    "ip": check_ip,
    "ports": check_ports,
    "http": check_http,
    "headers": check_headers,
    "cert": check_cert,
    "trace": check_trace,
    "route": check_route,
    "whois": check_whois,
}


def cmd_check(args):
    if not args:
        return err("Usage: check <type> [target]")
    subtype = args[0]
    handler = CHECK_HANDLERS.get(subtype)
    if not handler:
        return err(f"Unknown check type: {subtype}")
    return handler(args[1:])


# ---------------------------------------------------------------------------
# RUN (safe placeholder, no code execution)
# ---------------------------------------------------------------------------

GITHUB_SHORT_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GITHUB_URL_RE = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(\.git)?/?$")


def cmd_run(args):
    if not args:
        return err('Usage: run "user/project"')
    raw = args[0]
    owner, repo = None, None

    m = GITHUB_URL_RE.match(raw)
    if m:
        owner, repo = m.group(1), m.group(2)
    elif GITHUB_SHORT_RE.match(raw):
        owner, repo = raw.split("/", 1)
    else:
        return err(f"Invalid repository reference: {raw}")

    info_lines = [
        "[RUN]",
        "",
        f"Repository : {owner}/{repo}",
        "Source     : GitHub",
    ]

    if requests is not None:
        try:
            api_url = f"https://api.github.com/repos/{owner}/{repo}"
            resp = requests.get(api_url, timeout=5, headers={"Accept": "application/vnd.github+json"})
            if resp.status_code == 200:
                data = resp.json()
                info_lines.append("Status     : READY")
                info_lines.append(f"Description: {data.get('description') or 'n/a'}")
                info_lines.append(f"Stars      : {data.get('stargazers_count', 'n/a')}")
                info_lines.append(f"Default Br.: {data.get('default_branch', 'n/a')}")
            elif resp.status_code == 404:
                info_lines.append("Status     : NOT FOUND")
            else:
                info_lines.append(f"Status     : UNKNOWN (HTTP {resp.status_code})")
        except requests.exceptions.RequestException:
            info_lines.append("Status     : UNKNOWN (network error)")
    else:
        info_lines.append("Status     : READY (repo metadata lookup unavailable)")

    info_lines.append("")
    info_lines.append("Execution sandbox is not enabled in this version.")
    return ok("\n".join(info_lines))


# ---------------------------------------------------------------------------
# DATA commands
# ---------------------------------------------------------------------------

def cmd_hash(args):
    if len(args) < 2 or args[0] != "sha256":
        return err('Usage: hash sha256 "text"')
    text = args[1]
    digest = hashlib.sha256(text.encode()).hexdigest()
    return ok(digest)


def cmd_encode(args):
    if len(args) < 2 or args[0] != "base64":
        return err('Usage: encode base64 "text"')
    text = args[1]
    return ok(base64.b64encode(text.encode()).decode())


def cmd_decode(args):
    if len(args) < 2 or args[0] != "base64":
        return err('Usage: decode base64 "text"')
    text = args[1]
    try:
        return ok(base64.b64decode(text).decode(errors="replace"))
    except Exception as e:
        return err(f"Decode failed: {e}")


def _safe_data_path(filename: str):
    if not is_safe_filename(filename):
        return None
    path = os.path.normpath(os.path.join(DATA_DIR, filename))
    if not path.startswith(os.path.normpath(DATA_DIR)):
        return None
    return path


def cmd_json(args):
    if not args:
        return err("Usage: json filename.json")
    path = _safe_data_path(args[0])
    if not path:
        return err("Invalid filename.")
    if not os.path.isfile(path):
        return err(f"File not found: {args[0]}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return ok(json.dumps(data, indent=2, ensure_ascii=False))
    except json.JSONDecodeError as e:
        return err(f"Invalid JSON: {e}")
    except Exception as e:
        return err(f"Could not read file: {e}")


def cmd_search(args):
    if len(args) < 2:
        return err('Usage: search "term" filename.txt')
    term, filename = args[0], args[1]
    path = _safe_data_path(filename)
    if not path:
        return err("Invalid filename.")
    if not os.path.isfile(path):
        return err(f"File not found: {filename}")
    try:
        matches = []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, start=1):
                if term.lower() in line.lower():
                    matches.append(f"{i}: {line.rstrip()}")
                if len(matches) >= 50:
                    break
        if not matches:
            return ok(f'No matches for "{term}" in {filename}.')
        return ok("\n".join(matches))
    except Exception as e:
        return err(f"Search failed: {e}")


# ---------------------------------------------------------------------------
# SYSTEM commands
# ---------------------------------------------------------------------------

def _require_psutil():
    if psutil is None:
        return err("System info unavailable: psutil not installed.")
    return None


def cmd_system(_args):
    error = _require_psutil()
    if error:
        return error
    return ok(
        f"CPU cores : {psutil.cpu_count(logical=True)}\n"
        f"CPU usage : {psutil.cpu_percent(interval=0.2)}%\n"
        f"Memory    : {psutil.virtual_memory().percent}% used\n"
        f"Disk      : {psutil.disk_usage('/').percent}% used\n"
        f"Processes : {len(psutil.pids())}\n"
        f"Uptime    : {_format_uptime()}"
    )


def cmd_cpu(_args):
    error = _require_psutil()
    if error:
        return error
    return ok(f"CPU usage: {psutil.cpu_percent(interval=0.3)}% ({psutil.cpu_count()} cores)")


def cmd_memory(_args):
    error = _require_psutil()
    if error:
        return error
    mem = psutil.virtual_memory()
    return ok(
        f"Total : {mem.total // (1024 ** 2)} MB\n"
        f"Used  : {mem.used // (1024 ** 2)} MB\n"
        f"Free  : {mem.available // (1024 ** 2)} MB\n"
        f"Usage : {mem.percent}%"
    )


def cmd_disk(_args):
    error = _require_psutil()
    if error:
        return error
    disk = psutil.disk_usage("/")
    return ok(
        f"Total : {disk.total // (1024 ** 3)} GB\n"
        f"Used  : {disk.used // (1024 ** 3)} GB\n"
        f"Free  : {disk.free // (1024 ** 3)} GB\n"
        f"Usage : {disk.percent}%"
    )


def cmd_process(_args):
    error = _require_psutil()
    if error:
        return error
    return ok(f"Running processes visible to app environment: {len(psutil.pids())}")


def _format_uptime():
    seconds = int(time.time() - START_TIME)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m}m {s}s (application process)"


def cmd_uptime(_args):
    return ok(_format_uptime())


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

COMMANDS = {
    "help": cmd_help,
    "clear": cmd_clear,
    "history": cmd_history,
    "version": cmd_version,
    "about": cmd_about,
    "exit": cmd_exit,
    "run": cmd_run,
    "check": cmd_check,
    "target": cmd_target,
    "alias": cmd_alias,
    "hash": cmd_hash,
    "encode": cmd_encode,
    "decode": cmd_decode,
    "json": cmd_json,
    "search": cmd_search,
    "system": cmd_system,
    "cpu": cmd_cpu,
    "memory": cmd_memory,
    "disk": cmd_disk,
    "process": cmd_process,
    "uptime": cmd_uptime,
}


def ok(message: str):
    return {"success": True, "output": message}


def err(message: str):
    return {"success": False, "output": message}


def parse_and_run(raw_command: str):
    raw_command = (raw_command or "").strip()
    if not raw_command:
        return err("Empty command.")
    try:
        tokens = shlex.split(raw_command)
    except ValueError as e:
        return err(f"Could not parse command: {e}")
    if not tokens:
        return err("Empty command.")
    name, args = tokens[0].lower(), tokens[1:]
    handler = COMMANDS.get(name)
    if not handler:
        return err(f'Unknown command: "{name}". Type "help" for a list of commands.')
    try:
        return handler(args)
    except Exception as e:  # never crash on bad input
        return err(f"Command failed: {e}")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html", version=APP_VERSION)


@app.route("/api/command", methods=["POST"])
def api_command():
    payload = request.get_json(silent=True) or {}
    raw_command = payload.get("command", "")
    result = parse_and_run(raw_command)
    return jsonify(result)


@app.errorhandler(404)
def not_found(_e):
    return jsonify({"success": False, "output": "Not found."}), 404


@app.errorhandler(500)
def server_error(_e):
    return jsonify({"success": False, "output": "Internal server error."}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
