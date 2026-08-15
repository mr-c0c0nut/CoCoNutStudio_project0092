# -*- coding: utf-8 -*-
"""
M.C.O (Machine Command Operator) — web terminal backend.
Language: COCOTHON v0.1
"""

import base64
import hashlib
import ipaddress
import json
import logging
import os
import platform
import re
import secrets
import shlex
import socket
import ssl
import time
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, render_template, request, session

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

APP_START_TIME = time.time()
MCO_VERSION = "0.1.0"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024
app.config["JSON_SORT_KEYS"] = False

DEBUG_MODE = os.environ.get("FLASK_DEBUG", "0") == "1"

logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
app.logger.setLevel(logging.DEBUG if DEBUG_MODE else logging.INFO)

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

MAX_HISTORY = 50
MAX_ALIASES = 20
NETWORK_TIMEOUT = 4
GITHUB_TIMEOUT = 6
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 8080, 8443]
MAX_TEXT_READ_BYTES = 200 * 1024
MAX_SEARCH_MATCHES = 50

_RATE_WINDOW_SECONDS = 10
_RATE_MAX_REQUESTS = 30
_rate_buckets = {}


def _rate_limited(ip: str) -> bool:
    now = time.time()
    bucket = _rate_buckets.setdefault(ip, [])
    cutoff = now - _RATE_WINDOW_SECONDS
    while bucket and bucket[0] < cutoff:
        bucket.pop(0)
    if len(bucket) >= _RATE_MAX_REQUESTS:
        return True
    bucket.append(now)
    return False


class CommandError(Exception):
    pass


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_hostname(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    host = value[:-1] if value.endswith(".") else value
    label = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
    parts = host.split(".")
    return all(label.match(p) for p in parts)


def is_valid_target(value: str) -> bool:
    return bool(value) and (is_valid_ip(value) or is_valid_hostname(value))


def safe_data_path(filename: str) -> str:
    name = os.path.basename(filename.strip())
    if not name:
        raise CommandError("Invalid filename.")
    full_path = os.path.normpath(os.path.join(DATA_DIR, name))
    if not full_path.startswith(os.path.normpath(DATA_DIR) + os.sep) and full_path != DATA_DIR:
        raise CommandError("Invalid filename.")
    if not os.path.isfile(full_path):
        raise CommandError(f"File not found in data/: {name}")
    return full_path


def get_history():
    return session.get("history", [])


def push_history(raw_input: str):
    hist = session.get("history", [])
    hist.append(raw_input)
    if len(hist) > MAX_HISTORY:
        hist = hist[-MAX_HISTORY:]
    session["history"] = hist
    session.modified = True


def get_aliases():
    return session.get("aliases", {})


def resolve_target(args, require=True):
    aliases = get_aliases()
    if args:
        candidate = args[0]
        return aliases.get(candidate, candidate)
    current = session.get("target")
    if current:
        return current
    if require:
        raise CommandError("No target selected. Use: target <host>  or  check <type> <host>")
    return None


def cmd_help(args, ctx):
    return [
        "[CORE]",
        "help                          Show this help",
        "clear                         Clear the terminal",
        "history                       Show command history",
        "version                       Show M.C.O version",
        "about                         About M.C.O / COCOTHON",
        "exit                          End the session",
        "",
        "[TARGET]",
        'target <host>                 Set current target',
        'alias <name> = <value>        Create a target shortcut',
        "",
        "[CHECK]",
        "check ping <target>",
        "check dns <target>",
        "check ip <target>",
        "check ports <target>",
        "check http <target>",
        "check headers <target>",
        "check cert <target>",
        "check trace <target>",
        "check route <target>",
        "check whois <target>",
        "",
        "[RUN]",
        'run "owner/repository"',
        'run "https://github.com/owner/repository"',
        "",
        "[DATA]",
        'hash sha256 "text"',
        'encode base64 "text"',
        'decode base64 "text"',
        "json <file>",
        'search "term" <file>',
        "",
        "[SYSTEM]",
        "system", "cpu", "memory", "disk", "process", "uptime",
        "",
        '(target argument may be omitted if "target" or an alias is set)',
    ]


def cmd_version(args, ctx):
    return [f"M.C.O v{MCO_VERSION}  (COCOTHON language v0.1)"]


def cmd_about(args, ctx):
    return [
        "M.C.O — a friendly web terminal for basic network diagnostics",
        "and small data utilities, built on the COCOTHON command language.",
        "",
        "All commands run through a fixed whitelist on the server —",
        "there is no arbitrary code or shell execution.",
    ]


def cmd_history(args, ctx):
    hist = get_history()
    if not hist:
        return ["(history is empty)"]
    return [f"{i + 1:>3}  {cmd}" for i, cmd in enumerate(hist)]


def cmd_exit(args, ctx):
    return [
        "Session terminated.",
        "(This is a web terminal — refresh the page to start a new session.)",
    ]


def cmd_clear(args, ctx):
    return [""]


def cmd_target(args, ctx):
    if not args:
        current = session.get("target")
        return [f"Current target: {current}"] if current else ["No target selected."]
    value = args[0]
    if not is_valid_target(value):
        raise CommandError(f"Invalid target: {value}")
    session["target"] = value
    session.modified = True
    return ["Target set:", value]


def cmd_alias(args, ctx):
    if len(args) != 3 or args[1] != "=":
        raise CommandError('Usage: alias <name> = <value>')
    name, _, value = args
    if not re.match(r"^[A-Za-z0-9_-]{1,32}$", name):
        raise CommandError("Alias name must be alphanumeric (max 32 chars).")
    if not is_valid_target(value):
        raise CommandError(f"Invalid alias value: {value}")
    aliases = get_aliases()
    if name not in aliases and len(aliases) >= MAX_ALIASES:
        raise CommandError(f"Alias limit reached ({MAX_ALIASES}). Remove one first.")
    aliases[name] = value
    session["aliases"] = aliases
    session.modified = True
    return [f"Alias created: {name} = {value}"]


def _split_scheme_host(target: str):
    match = re.match(r"^(https?)://([^/]+)", target)
    if match:
        return match.group(1), match.group(2).split(":")[0]
    return None, target.split("/")[0].split(":")[0]


def check_ping(target, ctx):
    _, host = _split_scheme_host(target)
    if not is_valid_target(host):
        raise CommandError(f"Invalid target: {host}")
    for port in (443, 80):
        start = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=NETWORK_TIMEOUT):
                latency_ms = round((time.perf_counter() - start) * 1000, 1)
                return [
                    "[CHECK / PING]", "",
                    f"Target : {host}",
                    "Status : ONLINE",
                    f"Latency: {latency_ms} ms  (TCP connect on port {port})",
                    "", "Completed.",
                ]
        except (socket.timeout, OSError):
            continue
    return ["[CHECK / PING]", "", f"Target : {host}", "Status : OFFLINE / UNREACHABLE", "", "Completed."]


def check_dns(target, ctx):
    _, host = _split_scheme_host(target)
    if not is_valid_hostname(host) and not is_valid_ip(host):
        raise CommandError(f"Invalid target: {host}")
    try:
        hostname, aliases, ip_list = socket.gethostbyname_ex(host)
    except socket.gaierror:
        raise CommandError(f"Could not resolve host:\n{host}")
    except socket.timeout:
        raise CommandError(f"DNS lookup timed out for:\n{host}")
    lines = ["[CHECK / DNS]", "", f"Target   : {host}", f"Resolved : {hostname}", "Addresses:"]
    for ip in ip_list[:10]:
        lines.append(f"  - {ip}")
    if aliases:
        lines.append("Aliases  :")
        for a in aliases[:5]:
            lines.append(f"  - {a}")
    lines += ["", "Completed."]
    return lines


def check_ip(target, ctx):
    _, host = _split_scheme_host(target)
    if is_valid_ip(host):
        try:
            hostname, _, _ = socket.gethostbyaddr(host)
            return ["[CHECK / IP]", "", f"IP           : {host}", f"Reverse DNS  : {hostname}", "", "Completed."]
        except (socket.herror, socket.gaierror):
            return ["[CHECK / IP]", "", f"IP           : {host}", "Reverse DNS  : (none found)", "", "Completed."]
        except socket.timeout:
            raise CommandError("Reverse DNS lookup timed out.")
    if not is_valid_hostname(host):
        raise CommandError(f"Invalid target: {host}")
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        raise CommandError(f"Could not resolve host:\n{host}")
    return ["[CHECK / IP]", "", f"Host : {host}", f"IP   : {ip}", "", "Completed."]


def check_ports(target, ctx):
    _, host = _split_scheme_host(target)
    if not is_valid_target(host):
        raise CommandError(f"Invalid target: {host}")
    lines = ["[CHECK / PORTS]", "", f"Target: {host}", f"(scanning {len(COMMON_PORTS)} common ports)", ""]
    for port in COMMON_PORTS:
        try:
            with socket.create_connection((host, port), timeout=0.8):
                lines.append(f"  {port:<6} OPEN")
        except socket.timeout:
            lines.append(f"  {port:<6} filtered")
        except OSError:
            lines.append(f"  {port:<6} closed")
    lines += ["", "Completed."]
    return lines


def check_http(target, ctx):
    scheme, host = _split_scheme_host(target)
    if not is_valid_target(host):
        raise CommandError(f"Invalid target: {host}")
    schemes_to_try = [scheme] if scheme else ["https", "http"]
    last_error = None
    for s in schemes_to_try:
        url = f"{s}://{host}"
        try:
            start = time.perf_counter()
            resp = requests.get(url, timeout=NETWORK_TIMEOUT, allow_redirects=True, stream=True)
            elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
            body_preview = next(resp.iter_content(chunk_size=2048), b"")
            resp.close()
            return [
                "[CHECK / HTTP]", "",
                f"URL         : {url}",
                f"Status      : {resp.status_code} {resp.reason}",
                f"Time        : {elapsed_ms} ms",
                f"Content-Type: {resp.headers.get('Content-Type', 'unknown')}",
                f"Body size   : {len(body_preview)}+ bytes (preview only)",
                "", "Completed.",
            ]
        except requests.exceptions.SSLError as e:
            last_error = f"TLS/SSL error: {e}"
        except requests.exceptions.ConnectionError:
            last_error = "Connection failed."
        except requests.exceptions.Timeout:
            last_error = "Request timed out."
        except requests.exceptions.RequestException as e:
            last_error = str(e)
    raise CommandError(f"Could not reach {host}:\n{last_error}")


def check_headers(target, ctx):
    scheme, host = _split_scheme_host(target)
    if not is_valid_target(host):
        raise CommandError(f"Invalid target: {host}")
    schemes_to_try = [scheme] if scheme else ["https", "http"]
    last_error = None
    for s in schemes_to_try:
        url = f"{s}://{host}"
        try:
            resp = requests.get(url, timeout=NETWORK_TIMEOUT, allow_redirects=True, stream=True)
            resp.close()
            lines = ["[CHECK / HEADERS]", "", f"URL: {url}", ""]
            for k, v in list(resp.headers.items())[:25]:
                lines.append(f"  {k}: {v[:200]}")
            lines += ["", "Completed."]
            return lines
        except requests.exceptions.ConnectionError:
            last_error = "Connection failed."
        except requests.exceptions.Timeout:
            last_error = "Request timed out."
        except requests.exceptions.RequestException as e:
            last_error = str(e)
    raise CommandError(f"Could not reach {host}:\n{last_error}")


def check_cert(target, ctx):
    _, host = _split_scheme_host(target)
    if not is_valid_target(host):
        raise CommandError(f"Invalid target: {host}")
    try:
        ctx_ssl = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=NETWORK_TIMEOUT) as sock:
            with ctx_ssl.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except socket.timeout:
        raise CommandError(f"Connection timed out:\n{host}:443")
    except ssl.SSLError as e:
        raise CommandError(f"TLS error:\n{e}")
    except OSError as e:
        raise CommandError(f"Could not connect:\n{host}:443\n{e}")

    def _name(field):
        return ", ".join(f"{k}={v}" for tup in cert.get(field, []) for k, v in tup)

    return [
        "[CHECK / CERT]", "",
        f"Host       : {host}",
        f"Subject    : {_name('subject') or 'unknown'}",
        f"Issuer     : {_name('issuer') or 'unknown'}",
        f"Valid from : {cert.get('notBefore', 'unknown')}",
        f"Valid until: {cert.get('notAfter', 'unknown')}",
        "", "Completed.",
    ]


def check_trace(target, ctx):
    return [
        "[CHECK / TRACE]", "",
        "NOT AVAILABLE IN V0.1 — SAFE PLACEHOLDER",
        "Traceroute requires raw ICMP sockets, not permitted on Render.",
    ]


def check_route(target, ctx):
    return [
        "[CHECK / ROUTE]", "",
        "NOT AVAILABLE IN V0.1 — SAFE PLACEHOLDER",
        "Reading the system routing table is not exposed in this hosting environment.",
    ]


def check_whois(target, ctx):
    _, host = _split_scheme_host(target)
    if not is_valid_hostname(host):
        raise CommandError(f"Invalid target: {host}")

    def query(domain, server, depth=0):
        if depth > 3:
            return ""
        try:
            with socket.create_connection((server, 43), timeout=NETWORK_TIMEOUT) as s:
                s.sendall((domain + "\r\n").encode())
                chunks, total = [], 0
                s.settimeout(NETWORK_TIMEOUT)
                while total < 8192:
                    data = s.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
                    total += len(data)
                text = b"".join(chunks).decode(errors="ignore")
        except (socket.timeout, OSError):
            return ""
        referral = re.search(r"(?im)^\s*(?:refer|whois server)\s*:\s*(\S+)", text)
        if referral and depth < 2:
            deeper = query(domain, referral.group(1), depth + 1)
            if deeper:
                return deeper
        return text

    result = query(host, "whois.iana.org")
    if not result:
        raise CommandError(f"WHOIS lookup failed or timed out for:\n{host}")
    trimmed = result.strip().splitlines()
    trimmed = [l for l in trimmed if l.strip() and not l.strip().startswith("%")][:40]
    return ["[CHECK / WHOIS]", "", f"Target: {host}", ""] + trimmed + ["", "Completed."]


CHECK_SUBCOMMANDS = {
    "ping": check_ping, "dns": check_dns, "ip": check_ip, "ports": check_ports,
    "http": check_http, "headers": check_headers, "cert": check_cert,
    "trace": check_trace, "route": check_route, "whois": check_whois,
}


def cmd_check(args, ctx):
    if not args:
        raise CommandError(f"Usage: check <type> <target>\nTypes: {', '.join(CHECK_SUBCOMMANDS)}")
    sub = args[0].lower()
    if sub not in CHECK_SUBCOMMANDS:
        raise CommandError(f"Unknown check command: {sub}")
    target = resolve_target(args[1:])
    return CHECK_SUBCOMMANDS[sub](target, ctx)


# ==================================================================
# RUN COMMAND — rewritten
# ==================================================================

# Matches https://github.com/owner/repo (with or without trailing slash,
# .git suffix, or extra path segments after the repo name).
GITHUB_RE_FULL = re.compile(
    r"^https?://(?:www\.)?github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)/"
    r"([A-Za-z0-9._-]+?)(?:\.git)?(?:/.*)?$"
)
# Matches owner/repo shorthand only (no scheme, no extra slashes/segments).
GITHUB_RE_SHORT = re.compile(
    r"^([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)/([A-Za-z0-9._-]+)$"
)

ENTRY_POINT_CANDIDATES = [
    "app.py", "main.py", "index.py", "package.json", "requirements.txt",
]


def _parse_repo_ref(ref: str):
    """Return (owner, repo) or None. Explicitly rejects raw.githubusercontent.com
    and any other host — only github.com URLs or bare 'owner/repo' shorthand
    are supported in v0.1, per spec."""
    ref = ref.strip()
    if not ref:
        return None

    m = GITHUB_RE_FULL.match(ref)
    if m:
        return m.group(1), m.group(2)

    # If it looks like a URL but isn't a github.com one, reject explicitly
    # rather than falling through to the shorthand pattern.
    if re.match(r"^https?://", ref):
        return None

    m = GITHUB_RE_SHORT.match(ref)
    if m:
        return m.group(1), m.group(2)

    return None


def _github_get(url, timeout=GITHUB_TIMEOUT):
    """Single point of contact with the GitHub API. Never swallows the
    real exception — logs it with app.logger.exception so Render Logs
    shows the actual cause, then raises a specific CommandError."""
    try:
        return requests.get(
            url,
            timeout=timeout,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "MCO-Terminal",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
    except requests.exceptions.Timeout as e:
        app.logger.exception("GitHub request timed out | url=%s", url)
        raise CommandError("GitHub request timed out.") from e
    except requests.exceptions.SSLError as e:
        app.logger.exception("GitHub TLS error | url=%s", url)
        raise CommandError("GitHub connection failed.") from e
    except requests.exceptions.ConnectionError as e:
        app.logger.exception("GitHub connection failed | url=%s", url)
        raise CommandError("GitHub connection failed.") from e
    except requests.exceptions.RequestException as e:
        app.logger.exception("GitHub request failed | url=%s", url)
        raise CommandError("GitHub connection failed.") from e


def _detect_entry_point(owner, repo, default_branch):
    """Look at the repo's root tree and return the first matching common
    entry-point filename, or None. Failures here are non-fatal — RUN
    still reports repository info even if the tree lookup fails."""
    tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{default_branch}"
    try:
        resp = requests.get(
            tree_url,
            timeout=GITHUB_TIMEOUT,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "MCO-Terminal",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
    except requests.exceptions.RequestException as e:
        app.logger.exception("GitHub tree lookup failed | owner=%s repo=%s", owner, repo)
        return None

    if resp.status_code != 200:
        return None

    try:
        tree = resp.json().get("tree", [])
    except ValueError:
        app.logger.exception("GitHub tree response was not valid JSON | owner=%s repo=%s", owner, repo)
        return None

    names_at_root = {
        item.get("path") for item in tree
        if isinstance(item, dict) and item.get("type") == "blob" and "/" not in (item.get("path") or "")
    }
    for candidate in ENTRY_POINT_CANDIDATES:
        if candidate in names_at_root:
            return candidate
    return None


def cmd_run(args, ctx):
    if not args:
        raise CommandError('Usage: run "owner/repository"  or  run "https://github.com/owner/repository"')

    ref = args[0]
    parsed = _parse_repo_ref(ref)
    if not parsed:
        raise CommandError(
            'Invalid repository reference.\n'
            'Supported formats:\n'
            '  run "owner/repository"\n'
            '  run "https://github.com/owner/repository"'
        )
    owner, repo = parsed

    repo_url = f"https://api.github.com/repos/{owner}/{repo}"
    resp = _github_get(repo_url)

    if resp.status_code == 404:
        return [
            "[ M.C.O / RUN ]", "",
            f"Repository : {owner}/{repo}",
            "Status     : NOT FOUND", "",
            "Repository not found.",
        ]

    if resp.status_code != 200:
        app.logger.error(
            "GitHub API returned unexpected status | owner=%s repo=%s status=%s body=%s",
            owner, repo, resp.status_code, resp.text[:300],
        )
        raise CommandError(f"GitHub connection failed. (HTTP {resp.status_code})")

    try:
        info = resp.json()
    except ValueError as e:
        app.logger.exception("GitHub repo response was not valid JSON | owner=%s repo=%s", owner, repo)
        raise CommandError("GitHub connection failed.") from e

    default_branch = info.get("default_branch") or "main"
    description = (info.get("description") or "(no description)")[:200]
    visibility = "PRIVATE" if info.get("private") else "PUBLIC"
    html_url = info.get("html_url") or f"https://github.com/{owner}/{repo}"

    entry = _detect_entry_point(owner, repo, default_branch)

    lines = [
        "[ M.C.O / RUN ]", "",
        f"Repository : {owner}/{repo}",
        "Status     : FOUND",
        f"Owner      : {owner}",
        f"Description: {description}",
        f"Branch     : {default_branch}",
        f"Visibility : {visibility}",
        f"URL        : {html_url}",
        f"Entry      : {entry if entry else '(none of the common entry points found)'}",
        "",
        "Execution:",
        "SANDBOX REQUIRED",
        "NOT AVAILABLE IN V0.1 — SAFE PLACEHOLDER",
        "(Repository code is never downloaded or executed by M.C.O.)",
    ]
    return lines


# ==================================================================
# DATA COMMANDS
# ==================================================================

HASH_ALGOS = {"sha256", "sha1", "sha512", "md5"}


def cmd_hash(args, ctx):
    if len(args) != 2:
        raise CommandError('Usage: hash <algorithm> "text"')
    algo, text = args[0].lower(), args[1]
    if algo not in HASH_ALGOS:
        raise CommandError(f"Unsupported algorithm: {algo}\nSupported: {', '.join(sorted(HASH_ALGOS))}")
    digest = hashlib.new(algo, text.encode("utf-8")).hexdigest()
    return ["[HASH]", "", f"Algorithm: {algo}", f"Input    : {text}", f"Digest   : {digest}"]


def cmd_encode(args, ctx):
    if len(args) != 2 or args[0].lower() != "base64":
        raise CommandError('Usage: encode base64 "text"')
    text = args[1]
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    return ["[ENCODE / BASE64]", "", f"Input : {text}", f"Output: {encoded}"]


def cmd_decode(args, ctx):
    if len(args) != 2 or args[0].lower() != "base64":
        raise CommandError('Usage: decode base64 "text"')
    text = args[1]
    try:
        decoded = base64.b64decode(text, validate=True).decode("utf-8")
    except Exception:
        raise CommandError("Invalid base64 input.")
    return ["[DECODE / BASE64]", "", f"Input : {text}", f"Output: {decoded}"]


def cmd_json(args, ctx):
    if len(args) != 1:
        raise CommandError("Usage: json <file>")
    path = safe_data_path(args[0])
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read(MAX_TEXT_READ_BYTES)
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise CommandError(f"Invalid JSON in {args[0]}:\n{e}")
    except UnicodeDecodeError:
        raise CommandError(f"File is not valid UTF-8 text: {args[0]}")
    pretty = json.dumps(data, indent=2, ensure_ascii=False)
    lines = pretty.splitlines()
    truncated = len(lines) > 60
    lines = lines[:60]
    out = [f"[JSON] {args[0]}", ""] + lines
    if truncated:
        out.append("... (truncated)")
    return out


def cmd_search(args, ctx):
    if len(args) != 2:
        raise CommandError('Usage: search "term" <file>')
    term, filename = args[0], args[1]
    path = safe_data_path(filename)
    matches = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            bytes_read = 0
            for lineno, text_line in enumerate(f, start=1):
                bytes_read += len(text_line.encode("utf-8", errors="ignore"))
                if bytes_read > MAX_TEXT_READ_BYTES:
                    break
                if term.lower() in text_line.lower():
                    matches.append(f"  {lineno:>5}: {text_line.rstrip()[:200]}")
                    if len(matches) >= MAX_SEARCH_MATCHES:
                        break
    except UnicodeDecodeError:
        raise CommandError(f"File is not valid UTF-8 text: {filename}")
    if not matches:
        return [f'[SEARCH] "{term}" in {filename}', "", "No matches found."]
    return [f'[SEARCH] "{term}" in {filename}', ""] + matches + ["", f"{len(matches)} match(es)."]


def _uptime_str():
    seconds = int(time.time() - APP_START_TIME)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m}m {s}s"


def cmd_uptime(args, ctx):
    return [
        "[UPTIME]", "",
        f"Application uptime: {_uptime_str()}",
        f"Server time (UTC) : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}",
        "", "(Reflects this application process, not host system uptime.)",
    ]


def cmd_cpu(args, ctx):
    if not HAS_PSUTIL:
        return ["[CPU]", "", "psutil is not installed — CPU metrics unavailable."]
    percent = psutil.cpu_percent(interval=0.3)
    count = psutil.cpu_count(logical=True)
    return ["[CPU]", "", f"Logical cores: {count}", f"Usage        : {percent}%"]


def cmd_memory(args, ctx):
    if not HAS_PSUTIL:
        return ["[MEMORY]", "", "psutil is not installed — memory metrics unavailable."]
    vm = psutil.virtual_memory()
    return [
        "[MEMORY]", "",
        f"Total    : {vm.total // (1024 * 1024)} MB",
        f"Used     : {vm.used // (1024 * 1024)} MB",
        f"Available: {vm.available // (1024 * 1024)} MB",
        f"Usage    : {vm.percent}%",
    ]


def cmd_disk(args, ctx):
    if not HAS_PSUTIL:
        return ["[DISK]", "", "psutil is not installed — disk metrics unavailable."]
    du = psutil.disk_usage("/")
    return [
        "[DISK]", "",
        f"Total: {du.total // (1024 * 1024)} MB",
        f"Used : {du.used // (1024 * 1024)} MB",
        f"Free : {du.free // (1024 * 1024)} MB",
        f"Usage: {du.percent}%",
    ]


def cmd_process(args, ctx):
    pid = os.getpid()
    lines = ["[PROCESS]", "", f"PID          : {pid}", f"Python       : {platform.python_version()}"]
    if HAS_PSUTIL:
        try:
            p = psutil.Process(pid)
            lines.append(f"Memory (RSS) : {p.memory_info().rss // 1024} KB")
            lines.append(f"Threads      : {p.num_threads()}")
        except Exception:
            pass
    else:
        lines.append("(install psutil for extended process metrics)")
    return lines


def cmd_system(args, ctx):
    lines = [
        "[SYSTEM]", "",
        f"Platform  : {platform.system()} {platform.release()}",
        f"Python    : {platform.python_version()}",
        f"M.C.O     : v{MCO_VERSION}",
        f"Uptime    : {_uptime_str()}",
    ]
    if HAS_PSUTIL:
        lines.append(f"CPU usage : {psutil.cpu_percent(interval=0.2)}%")
        lines.append(f"Memory    : {psutil.virtual_memory().percent}%")
    return lines


COMMANDS = {
    "help": cmd_help, "clear": cmd_clear, "history": cmd_history,
    "version": cmd_version, "about": cmd_about, "exit": cmd_exit,
    "target": cmd_target, "alias": cmd_alias, "check": cmd_check,
    "run": cmd_run, "hash": cmd_hash, "encode": cmd_encode, "decode": cmd_decode,
    "json": cmd_json, "search": cmd_search, "system": cmd_system,
    "cpu": cmd_cpu, "memory": cmd_memory, "disk": cmd_disk,
    "process": cmd_process, "uptime": cmd_uptime,
}


def execute_command(raw_input: str):
    raw_input = raw_input.strip()
    if not raw_input:
        raise CommandError("Empty command.")
    if len(raw_input) > 500:
        raise CommandError("Command too long.")

    try:
        tokens = shlex.split(raw_input)
    except ValueError:
        raise CommandError("Unmatched quotes in command.")

    if not tokens:
        raise CommandError("Empty command.")

    cmd_name = tokens[0].lower()
    args = tokens[1:]

    if cmd_name not in COMMANDS:
        raise CommandError(f"Unknown command: {cmd_name}\nType 'help' to see available commands.")

    handler = COMMANDS[cmd_name]
    output_lines = handler(args, {})
    return cmd_name, output_lines


@app.route("/")
def index():
    return render_template("index.html", version=MCO_VERSION)


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "version": MCO_VERSION})


@app.route("/api/execute", methods=["POST"])
def api_execute():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if _rate_limited(client_ip):
        return jsonify({"ok": False, "success": False, "error": "Too many requests. Please slow down."}), 429

    body = request.get_json(silent=True)
    if not isinstance(body, dict) or "input" not in body:
        return jsonify({"ok": False, "success": False, "error": "Invalid request body."}), 400

    raw_input = str(body.get("input", ""))[:500]

    try:
        cmd_name, output_lines = execute_command(raw_input)
        push_history(raw_input)
        return jsonify({"ok": True, "success": True, "command": cmd_name, "output": output_lines})
    except CommandError as e:
        push_history(raw_input)
        return jsonify({"ok": False, "success": False, "error": str(e), "output": str(e)})
    except Exception as e:  # noqa: BLE001
        app.logger.exception("M.C.O command execution failed | input=%r", raw_input)
        if DEBUG_MODE:
            return jsonify({
                "ok": False, "success": False,
                "error": f"{type(e).__name__}: {e}",
                "output": f"{type(e).__name__}: {e}",
            }), 500
        return jsonify({
            "ok": False, "success": False,
            "error": "Internal error while running this command.",
            "output": "Internal error while running this command.",
        }), 500


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"ok": False, "success": False, "error": "Request too large."}), 413


@app.errorhandler(404)
def not_found(_e):
    return jsonify({"ok": False, "success": False, "error": "Not found."}), 404


@app.errorhandler(500)
def server_error(_e):
    app.logger.exception("Unhandled 500 error")
    return jsonify({"ok": False, "success": False, "error": "Internal server error."}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=DEBUG_MODE)
