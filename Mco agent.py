# -*- coding: utf-8 -*-
"""
M.C.O Local Agent
==================

A small local-only HTTP server that runs on the user's Windows machine
and exposes a STRICT WHITELIST of read-only / diagnostic operations to
the M.C.O web terminal running in the browser.

Design constraints (do not relax these without re-reading the whole
file and understanding why they exist):

  * Binds ONLY to 127.0.0.1. Never 0.0.0.0. Never a LAN interface.
  * A random port is chosen at startup (unless MCO_AGENT_PORT is set
    for local debugging) and a random bearer token is generated at
    startup. Neither is ever hard-coded or persisted to disk.
  * There is NO endpoint that executes an arbitrary shell command or
    arbitrary Python. Every capability is an explicit Python function
    registered in COMMANDS below. There is no "exec" / "eval" / "run
    this string as a command" endpoint anywhere in this file.
  * There is no file upload endpoint and no "run this executable"
    endpoint.
  * Windows UAC is never bypassed and never simulated. When an
    operation needs Administrator rights, the agent asks Windows to
    elevate a NEW process via the standard `runas` ShellExecute verb
    (see request_admin_elevation()). This always shows the real
    Windows UAC consent dialog. If the user (or Windows policy)
    denies it, the agent reports failure. There is no code path that
    pretends elevation succeeded when it did not, and no code path
    that touches the process token directly.
  * Every request (other than /health) must present the bearer token
    that was printed to stdout / written to the discovery file at
    startup. This stops a random web page from calling the agent
    silently.
  * Basic Origin allow-listing for the /diagnostic POST endpoint,
    since browsers still send Origin on same-origin XHR/fetch to
    localhost and it costs nothing to check it.

This file intentionally has NO third-party web framework dependency
beyond `psutil` (optional) so that PyInstaller output stays small and
auditable. It uses only Python's built-in http.server.
"""

import ctypes
import ipaddress
import json
import os
import platform
import secrets
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

AGENT_VERSION = "0.1.0"

# ---------------------------------------------------------------------------
# Startup identity: random port + random token. Never fixed, never stored
# in source, never written anywhere except a per-run discovery file that
# the browser-side JS is told to read (same-machine only).
# ---------------------------------------------------------------------------

AGENT_TOKEN = secrets.token_urlsafe(32)
BIND_HOST = "127.0.0.1"

# Optional fixed port for local debugging only (never set this in the
# packaged .exe / release build). If unset, the OS picks a free port.
_debug_port = os.environ.get("MCO_AGENT_PORT")
BIND_PORT = int(_debug_port) if _debug_port else 0

REQUEST_TIMEOUT_SECONDS = 10
MAX_BODY_BYTES = 8 * 1024

# Origins we accept requests from. Add your production domain here.
# 127.0.0.1 / localhost dev servers are always allowed.
ALLOWED_ORIGIN_SUFFIXES = (
    "://127.0.0.1",
    "://localhost",
)

DISCOVERY_FILENAME = os.path.join(
    os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
    ".mco_agent_discovery.json",
)


class AgentError(Exception):
    """Raised by a whitelisted command handler for an expected failure
    (bad input, operation not applicable, etc). Always safe to show
    the message to the user."""


# ---------------------------------------------------------------------------
# Windows UAC elevation — the ONLY way this agent ever gains Administrator
# rights. This calls the real Windows ShellExecute "runas" verb, which is
# what triggers the genuine UAC consent dialog. There is no other elevation
# path in this file: no token manipulation, no service installation trick,
# no "elevate silently" option.
# ---------------------------------------------------------------------------

def request_admin_elevation(executable, parameters, description):
    """
    Ask Windows to run `executable parameters` elevated, via the standard
    ShellExecuteW 'runas' verb. This ALWAYS shows the real UAC prompt to
    the logged-in user; there is no silent path.

    Returns a dict: {"granted": bool, "detail": str}

    granted=False covers both "user clicked No" and "UAC blocked/failed
    for another reason" — from this process's point of view those are
    indistinguishable (ShellExecute just fails with SE_ERR_ACCESSDENIED),
    and BOTH must be treated as "not elevated", never as success.
    """
    if platform.system() != "Windows":
        return {"granted": False, "detail": "Elevation is only supported on Windows."}

    try:
        # SW_NORMAL = 1. ShellExecuteW returns a value > 32 on success of
        # *launching* the elevated process (which itself only happens if
        # the user approved the UAC prompt). <= 32 means it did not launch,
        # which includes the user pressing "No" (ERROR_CANCELLED / 1223).
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", executable, parameters, None, 1
        )
        result_code = int(result)
        if result_code > 32:
            return {"granted": True, "detail": "Administrator privileges granted by Windows UAC."}

        if result_code == 5:
            detail = "Access denied."
        elif result_code == 1223:
            detail = "The user declined the Windows UAC prompt."
        else:
            detail = f"Windows declined to elevate (ShellExecute code {result_code})."
        return {"granted": False, "detail": detail}

    except Exception as exc:  # noqa: BLE001
        return {"granted": False, "detail": f"Elevation attempt failed: {exc}"}


# ---------------------------------------------------------------------------
# Whitelisted command implementations
#
# Every function here takes a plain dict of already-validated params and
# returns a plain JSON-serialisable dict. None of them build a shell string.
# None of them accept a free-form "command" field from the client.
# ---------------------------------------------------------------------------

def _iface_status_str(stats):
    if stats is None:
        return "unknown"
    return "up" if getattr(stats, "isup", False) else "down"


def cmd_myip(params):
    """Local network identity of THIS machine (the client), never the
    Flask server's IP — this only ever talks to interfaces on the box
    the agent is running on."""
    hostname = socket.gethostname()
    ipv4_list = []
    ipv6_list = []

    try:
        infos = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in infos:
            addr = sockaddr[0]
            if family == socket.AF_INET and addr not in ipv4_list:
                if not addr.startswith("127."):
                    ipv4_list.append(addr)
            elif family == socket.AF_INET6 and addr not in ipv6_list:
                if addr != "::1":
                    ipv6_list.append(addr)
    except socket.gaierror:
        pass

    if HAS_PSUTIL:
        try:
            for _, addr_list in psutil.net_if_addrs().items():
                for addr in addr_list:
                    if addr.family == socket.AF_INET and addr.address not in ipv4_list:
                        if not addr.address.startswith("127."):
                            ipv4_list.append(addr.address)
                    elif addr.family == socket.AF_INET6 and addr.address not in ipv6_list:
                        clean = addr.address.split("%")[0]
                        if clean != "::1" and clean not in ipv6_list:
                            ipv6_list.append(clean)
        except Exception:  # noqa: BLE001
            pass

    return {
        "hostname": hostname,
        "local_ipv4": ipv4_list,
        "local_ipv6": ipv6_list,
        "source": "local network interfaces of this machine (via socket/psutil)",
        "note": "This is the LOCAL AGENT machine's address, not the web server's address.",
    }


def cmd_public_ip(params):
    """Public IP as seen by a third-party HTTPS service. Source is always
    shown so the number is never presented as if the agent computed it
    locally."""
    service_url = "https://api.ipify.org?format=json"
    try:
        req = urllib.request.Request(service_url, headers={"User-Agent": "MCO-Agent"})
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return {
            "public_ip": body.get("ip", "unknown"),
            "source": service_url,
        }
    except Exception as exc:  # noqa: BLE001
        raise AgentError(f"Could not reach public IP service: {exc}")


def cmd_interfaces(params):
    if not HAS_PSUTIL:
        raise AgentError("psutil is not installed in the agent — interface listing unavailable.")
    result = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for name, addr_list in addrs.items():
        entry = {
            "name": name,
            "status": _iface_status_str(stats.get(name)),
            "addresses": [],
        }
        for a in addr_list:
            fam = str(a.family)
            if a.family == socket.AF_INET:
                fam = "IPv4"
            elif a.family == socket.AF_INET6:
                fam = "IPv6"
            elif hasattr(socket, "AF_PACKET") and a.family == socket.AF_PACKET:
                fam = "MAC"
            elif fam.endswith("AF_LINK"):
                fam = "MAC"
            entry["addresses"].append({"family": fam, "address": a.address})
        result.append(entry)
    return {"interfaces": result}


def cmd_system(params):
    info = {
        "os": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "agent_version": AGENT_VERSION,
    }
    return info


def cmd_cpu(params):
    if not HAS_PSUTIL:
        raise AgentError("psutil is not installed in the agent — CPU metrics unavailable.")
    return {
        "logical_cores": psutil.cpu_count(logical=True),
        "physical_cores": psutil.cpu_count(logical=False),
        "usage_percent": psutil.cpu_percent(interval=0.3),
    }


def cmd_memory(params):
    if not HAS_PSUTIL:
        raise AgentError("psutil is not installed in the agent — memory metrics unavailable.")
    vm = psutil.virtual_memory()
    return {
        "total_mb": vm.total // (1024 * 1024),
        "used_mb": vm.used // (1024 * 1024),
        "available_mb": vm.available // (1024 * 1024),
        "usage_percent": vm.percent,
    }


def cmd_disk(params):
    if not HAS_PSUTIL:
        raise AgentError("psutil is not installed in the agent — disk metrics unavailable.")
    drive = "C:\\" if platform.system() == "Windows" else "/"
    du = psutil.disk_usage(drive)
    return {
        "drive": drive,
        "total_mb": du.total // (1024 * 1024),
        "used_mb": du.used // (1024 * 1024),
        "free_mb": du.free // (1024 * 1024),
        "usage_percent": du.percent,
    }


def cmd_uptime(params):
    if HAS_PSUTIL:
        boot = psutil.boot_time()
        seconds = int(time.time() - boot)
        h, rem = divmod(seconds, 3600)
        m, s = divmod(rem, 60)
        return {"system_uptime": f"{h}h {m}m {s}s"}
    raise AgentError("psutil is not installed in the agent — uptime unavailable.")


def _validate_target(value):
    if not value or not isinstance(value, str) or len(value) > 253:
        raise AgentError("Invalid target.")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    import re
    label = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
    host = value[:-1] if value.endswith(".") else value
    if not all(label.match(p) for p in host.split(".")):
        raise AgentError("Invalid target.")
    return value


def diag_ping(target):
    host = _validate_target(target)
    for port in (443, 80):
        start = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=4):
                latency_ms = round((time.perf_counter() - start) * 1000, 1)
                return {"target": host, "status": "online", "latency_ms": latency_ms, "port": port}
        except (socket.timeout, OSError):
            continue
    return {"target": host, "status": "offline"}


def diag_dns(target):
    host = _validate_target(target)
    try:
        hostname, aliases, ip_list = socket.gethostbyname_ex(host)
    except socket.gaierror:
        raise AgentError(f"Could not resolve host: {host}")
    except socket.timeout:
        raise AgentError(f"DNS lookup timed out for: {host}")
    return {"target": host, "resolved": hostname, "addresses": ip_list, "aliases": aliases}


DIAGNOSTIC_TYPES = {
    "ping": diag_ping,
    "dns": diag_dns,
}


def cmd_diagnostic(params):
    diag_type = params.get("type")
    target = params.get("target")
    if diag_type not in DIAGNOSTIC_TYPES:
        raise AgentError(f"Unknown diagnostic type: {diag_type}. Allowed: {', '.join(DIAGNOSTIC_TYPES)}")
    return DIAGNOSTIC_TYPES[diag_type](target)


# ---------------------------------------------------------------------------
# Example ADMIN-REQUIRING whitelisted operation: flush the Windows DNS
# resolver cache. This is a stand-in for "any operation that genuinely
# needs Administrator". It demonstrates the full flow:
#
#   1. Client calls /diagnostic with type=flush_dns_admin.
#   2. Agent does NOT run anything yet — it returns requires_admin=true
#      and a human description. The FRONTEND is responsible for showing
#      the "[ SECURITY REQUEST ]" confirmation and only proceeding on "y".
#   3. Client re-calls with confirm=true. ONLY THEN does the agent call
#      request_admin_elevation(), which triggers the real Windows UAC
#      dialog via ShellExecute "runas". The elevated child process runs
#      `ipconfig /flushdns` — nothing else, no arbitrary string.
#   4. If the user denies UAC, the agent returns granted=false and the
#      operation is reported as cancelled. The agent process itself is
#      NEVER elevated — only the short-lived child command is.
# ---------------------------------------------------------------------------

ADMIN_OPERATIONS = {
    "flush_dns_admin": {
        "description": "Flush the Windows DNS resolver cache (ipconfig /flushdns).",
        "executable": "ipconfig",
        "parameters": "/flushdns",
    },
}


def cmd_admin_operation(params):
    op_name = params.get("operation")
    confirm = bool(params.get("confirm", False))

    if op_name not in ADMIN_OPERATIONS:
        raise AgentError(f"Unknown admin operation: {op_name}")

    op = ADMIN_OPERATIONS[op_name]

    if not confirm:
        # Step 2: describe what would happen. Do NOT touch the system yet.
        return {
            "requires_admin": True,
            "confirmed": False,
            "operation": op_name,
            "description": op["description"],
        }

    # Step 3: user already said "y" in the terminal UI. Now — and only
    # now — ask Windows for real elevation via the standard UAC prompt.
    elevation = request_admin_elevation(op["executable"], op["parameters"], op["description"])

    if not elevation["granted"]:
        return {
            "requires_admin": True,
            "confirmed": True,
            "granted": False,
            "operation": op_name,
            "detail": elevation["detail"],
        }

    return {
        "requires_admin": True,
        "confirmed": True,
        "granted": True,
        "operation": op_name,
        "detail": elevation["detail"],
    }


# ---------------------------------------------------------------------------
# HTTP layer — stdlib only. No arbitrary-command endpoint exists anywhere
# below. Every path maps to exactly one whitelisted Python function.
# ---------------------------------------------------------------------------

class AgentRequestHandler(BaseHTTPRequestHandler):
    server_version = f"MCOAgent/{AGENT_VERSION}"

    def log_message(self, fmt, *args):  # noqa: A003
        sys.stderr.write("[mco-agent] " + (fmt % args) + "\n")

    def _origin_allowed(self):
        origin = self.headers.get("Origin", "")
        if not origin:
            # Non-browser tools (curl, health checks) send no Origin.
            return True
        return any(suffix in origin for suffix in ALLOWED_ORIGIN_SUFFIXES)

    def _token_valid(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        provided = auth[len("Bearer "):]
        return secrets.compare_digest(provided, AGENT_TOKEN)

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):  # noqa: N802
        self._send_json(200, {"ok": True})

    def do_GET(self):  # noqa: N802
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "version": AGENT_VERSION})
            return

        if not self._origin_allowed():
            self._send_json(403, {"error": "Origin not allowed."})
            return
        if not self._token_valid():
            self._send_json(401, {"error": "Missing or invalid token."})
            return

        if self.path == "/info":
            self._send_json(200, {
                "version": AGENT_VERSION,
                "os": platform.system(),
                "capabilities": [
                    "myip", "public_ip", "interfaces", "system",
                    "cpu", "memory", "disk", "uptime", "diagnostic",
                    "admin_operation",
                ],
            })
            return

        self._send_json(404, {"error": "Not found."})

    def do_POST(self):  # noqa: N802
        if not self._origin_allowed():
            self._send_json(403, {"error": "Origin not allowed."})
            return
        if not self._token_valid():
            self._send_json(401, {"error": "Missing or invalid token."})
            return

        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > MAX_BODY_BYTES:
            self._send_json(400, {"error": "Invalid request body size."})
            return
        raw = self.rfile.read(length)
        try:
            params = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._send_json(400, {"error": "Invalid JSON body."})
            return
        if not isinstance(params, dict):
            self._send_json(400, {"error": "Body must be a JSON object."})
            return

        try:
            if self.path == "/myip":
                result = cmd_myip(params)
            elif self.path == "/public-ip":
                result = cmd_public_ip(params)
            elif self.path == "/interfaces":
                result = cmd_interfaces(params)
            elif self.path == "/system":
                result = cmd_system(params)
            elif self.path == "/cpu":
                result = cmd_cpu(params)
            elif self.path == "/memory":
                result = cmd_memory(params)
            elif self.path == "/disk":
                result = cmd_disk(params)
            elif self.path == "/uptime":
                result = cmd_uptime(params)
            elif self.path == "/diagnostic":
                result = cmd_diagnostic(params)
            elif self.path == "/admin-operation":
                result = cmd_admin_operation(params)
            else:
                self._send_json(404, {"error": "Not found."})
                return
        except AgentError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        except Exception as exc:  # noqa: BLE001
            self._send_json(500, {"error": f"Internal agent error: {exc}"})
            return

        self._send_json(200, {"ok": True, "result": result})


def _write_discovery_file(port):
    payload = {
        "port": port,
        "host": BIND_HOST,
        "token": AGENT_TOKEN,
        "version": AGENT_VERSION,
        "pid": os.getpid(),
    }
    try:
        with open(DISCOVERY_FILENAME, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        # Best-effort: keep this readable only by the current user where
        # the platform supports it. Not fatal if it fails.
        try:
            os.chmod(DISCOVERY_FILENAME, 0o600)
        except OSError:
            pass
    except OSError as exc:
        sys.stderr.write(f"[mco-agent] Warning: could not write discovery file: {exc}\n")


def main():
    server = ThreadingHTTPServer((BIND_HOST, BIND_PORT), AgentRequestHandler)
    actual_port = server.server_address[1]

    _write_discovery_file(actual_port)

    print("=" * 60)
    print(f"M.C.O Local Agent v{AGENT_VERSION}")
    print(f"Bound to : http://{BIND_HOST}:{actual_port}  (localhost only)")
    print(f"Token    : {AGENT_TOKEN}")
    print(f"Discovery: {DISCOVERY_FILENAME}")
    print("This window must stay open while you use M.C.O.")
    print("Close this window to stop the agent.")
    print("=" * 60)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            os.remove(DISCOVERY_FILENAME)
        except OSError:
            pass


if __name__ == "__main__":
    main()
