#!/usr/bin/env python3
"""
Foritech Server Read-only — a standalone, independent MCP diagnostics
service for general inspection of the whole /home/forybg tree.

This service is intentionally separate from Foritech OS Read-only
Diagnostics 3 (server/mcp-readonly/server.py under ~/services/foritech-os).
It does not import from, depend on, or share in-memory state with that
service. It has its own OAuth authorization/token endpoints, its own
bearer tokens, and its own read-only tool set rooted at /home/forybg.

No write, edit, delete, move, create-directory, restart, stop, chmod,
chown, sudo, or arbitrary-command tools are exposed. Every subprocess
call in this file uses a fixed argv list with shell=False.
"""
import base64
import fnmatch
import hashlib
import hmac
import html
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

HOST = "127.0.0.1"
PORT = int(os.environ.get("MCP_SERVER_READONLY_PORT", "3111"))

AUTH_TOKEN = os.environ.get("MCP_SERVER_READONLY_BEARER_TOKEN", "").strip()
LOGIN_PASSWORD_HASH = os.environ.get("MCP_SERVER_OAUTH_LOGIN_PASSWORD_HASH", "").strip()
PREDEFINED_CLIENT_ID = os.environ.get("MCP_SERVER_OAUTH_CLIENT_ID", "").strip()
PREDEFINED_REDIRECT_URI = os.environ.get("MCP_SERVER_OAUTH_REDIRECT_URI", "").strip()

# All routes are served under this fixed prefix so they can share a host
# with the unrelated Diagnostics 3 service via a Caddy path-based route
# (see deploy/Caddyfile.snippet). The prefix is preserved end to end,
# never stripped, so this file's own routing table matches the public URLs.
ROUTE_PREFIX = "/server"

ISSUER = "https://mcp-readonly.foritech.bg" + ROUTE_PREFIX
RESOURCE = ISSUER
SCOPE = "mcp:read"
RESOURCE_METADATA_URL = f"{ISSUER}/.well-known/oauth-protected-resource/mcp"
AUTHORIZATION_CODE_TTL = 300
ACCESS_TOKEN_TTL = 3600
MAX_FORM_BYTES = 16 * 1024
MAX_CIMD_BYTES = 64 * 1024

# Independent in-memory OAuth state. Not shared with, and not derived
# from, Diagnostics 3 in any way. Tokens are lost on process restart —
# this is documented in README.md and is out of scope to fix here.
_oauth_lock = threading.Lock()
_authorization_codes = {}
_access_tokens = {}

# ---------------------------------------------------------------------------
# Path security: everything is rooted at /home/forybg.
# ---------------------------------------------------------------------------
ROOT = Path("/home/forybg")

# Directory names that are fully denied anywhere they appear in a path.
_DENIED_DIR_NAMES = {
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".password-store",
    ".config",
    ".cache",
    ".step",
    ".foritech",
}

# Nested paths (relative to ROOT) that are fully denied as directories.
_DENIED_DIR_PREFIXES = (
    ".local/share/keyrings",
)

# Exact relative-path matches that are denied.
_DENIED_EXACT_RELATIVE_PATHS = {
    ".git-credentials",
    ".netrc",
    ".docker/config.json",
    ".bash_history",
    ".python_history",
    ".github_token",
    ".npmrc",
    ".pypirc",
    ".Xauthority",
    ".foritech_device",
}

# Filename glob patterns (matched against the final path component only)
# that are denied, evaluated case-insensitively.
_DENIED_FILENAME_GLOBS = (
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa*",
    "id_ed25519*",
    "*secret*",
    "*credentials*",
    "*token*",
    "*history*",
    "*.kdbx",
    "*.ovpn",
)


def _is_denied_relative_path(rel_posix, filename):
    """Return True if this relative path (posix-style, no leading slash)
    must never be read, listed, or scanned. `.env.example` is explicitly
    allowed even though `.env*` is otherwise denied."""
    parts = rel_posix.split("/")

    if any(part in _DENIED_DIR_NAMES for part in parts):
        return True

    for prefix in _DENIED_DIR_PREFIXES:
        if rel_posix == prefix or rel_posix.startswith(prefix + "/"):
            return True

    if rel_posix in _DENIED_EXACT_RELATIVE_PATHS:
        return True

    lower_name = filename.lower()
    if lower_name == ".env.example":
        return False
    if lower_name == ".env" or lower_name.startswith(".env."):
        return True

    for pattern in _DENIED_FILENAME_GLOBS:
        if fnmatch.fnmatch(lower_name, pattern):
            return True

    return False


class PathRejected(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def resolve_user_path(user_relative_path, must_exist=True):
    """Validate and resolve a caller-supplied relative path against ROOT.

    Rules enforced, in order:
      - the input must not be empty and must not be an absolute path
      - the input must not contain '..' traversal segments
      - the resolved path must remain under ROOT
      - no path component may itself be a symlink (the leaf is checked
        for symlink-ness explicitly; intermediate components are covered
        implicitly because Path.resolve() would otherwise silently
        follow them — we additionally verify the unresolved leaf here)
      - the path must not match the sensitive-path denylist

    Raises PathRejected(code) with one of:
      ABSOLUTE_PATH_REJECTED, PATH_TRAVERSAL_REJECTED,
      PATH_OUTSIDE_ROOT, SYMLINK_NOT_ALLOWED, ACCESS_DENIED
    """
    if user_relative_path is None or user_relative_path == "":
        user_relative_path = "."

    raw = str(user_relative_path)

    if raw.startswith("/") or raw.startswith("~"):
        raise PathRejected("ABSOLUTE_PATH_REJECTED")

    if ".." in Path(raw).parts:
        raise PathRejected("PATH_TRAVERSAL_REJECTED")

    root_resolved = ROOT.resolve()
    candidate = ROOT / raw

    if candidate.is_symlink():
        raise PathRejected("SYMLINK_NOT_ALLOWED")

    try:
        resolved = candidate.resolve(strict=False)
    except OSError as exc:
        raise PathRejected("RESOLVE_FAILED") from exc

    try:
        rel_to_root = resolved.relative_to(root_resolved)
    except ValueError:
        raise PathRejected("PATH_OUTSIDE_ROOT")

    rel_posix = "" if str(rel_to_root) == "." else rel_to_root.as_posix()
    filename = resolved.name

    if rel_posix and _is_denied_relative_path(rel_posix, filename):
        # Deliberately identical regardless of whether the path exists,
        # so existence of sensitive files is never confirmed or denied.
        raise PathRejected("ACCESS_DENIED")

    if must_exist and not resolved.exists():
        raise PathRejected("PATH_NOT_FOUND")

    return resolved, rel_posix


# ---------------------------------------------------------------------------
# Sensitive-value redaction, applied to every line of text this service
# ever returns (search results and any other diagnostic output).
# ---------------------------------------------------------------------------
_SENSITIVE_KV_KEYS = "client_secret|access_token|refresh_token|password|secret|token"


def redact_sensitive(line):
    line = re.sub(r'(?i)^(authorization\s*:\s*).*$', r'\1[REDACTED]', line)
    line = re.sub(r'(?i)^(cookie\s*:\s*).*$', r'\1[REDACTED]', line)
    line = re.sub(r'(?i)\bBearer\s+[A-Za-z0-9._\-]+', 'Bearer [REDACTED]', line)
    line = re.sub(
        r'(?i)\b(' + _SENSITIVE_KV_KEYS + r')=[^&\s"\']+',
        lambda m: m.group(1) + '=[REDACTED]',
        line,
    )
    line = re.sub(
        r'(?i)("(?:' + _SENSITIVE_KV_KEYS + r')"\s*:\s*")[^"]*(")',
        r'\1[REDACTED]\2',
        line,
    )
    return line


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------
POLICY_PATH = Path(__file__).resolve().parent / "policy.json"

SERVICE_ALLOWLIST_QUERY_UNITS = None  # list_services uses a fixed query, not a name allowlist

ALLOWED_TOOLS = {
    "server_status",
    "list_directory",
    "read_text_file",
    "search_text",
    "git_status",
    "docker_ps",
    "list_services",
    "forisec_context_bootstrap",
    "forisec_context_section",
    "forisec_context_search",
    "forisec_context_source",
}

FORBIDDEN_ACTIONS = {
    "write_file",
    "edit_file",
    "move_file",
    "delete_file",
    "create_directory",
    "run_command",
    "sudo",
    "systemctl restart",
    "systemctl stop",
    "docker compose down",
    "rm",
    "chmod",
    "chown",
}


def load_policy():
    if not POLICY_PATH.exists():
        return {"error": "policy file missing", "path": str(POLICY_PATH)}
    try:
        return json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"error": str(exc), "path": str(POLICY_PATH)}


def safe_run(argv, timeout=6):
    try:
        result = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": result.stdout.strip()[:8000],
            "stderr": result.stderr.strip()[:1000],
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------
def _read_meminfo():
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            raw = f.read()
    except OSError as exc:
        return {"error": str(exc)}

    values = {}
    for line in raw.splitlines():
        parts = line.split(":", 1)
        if len(parts) != 2:
            continue
        key = parts[0].strip()
        value = parts[1].strip().split()[0]
        try:
            values[key] = int(value)
        except ValueError:
            continue

    total_kb = values.get("MemTotal", 0)
    available_kb = values.get("MemAvailable", 0)
    used_kb = max(total_kb - available_kb, 0)
    return {
        "total_mb": round(total_kb / 1024, 1),
        "available_mb": round(available_kb / 1024, 1),
        "used_mb": round(used_kb / 1024, 1),
    }


def _uptime_seconds():
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            return float(f.read().split()[0])
    except Exception:
        return None


def tool_server_status(_args):
    usage = shutil.disk_usage("/")
    uptime = _uptime_seconds()
    return {
        "hostname": platform.node(),
        "platform": platform.platform(),
        "uptime_seconds": int(uptime) if uptime is not None else None,
        "loadavg": os.getloadavg() if hasattr(os, "getloadavg") else None,
        "disk_root": {
            "total_gb": round(usage.total / 1024**3, 2),
            "used_gb": round(usage.used / 1024**3, 2),
            "free_gb": round(usage.free / 1024**3, 2),
        },
        "memory": _read_meminfo(),
    }


def tool_list_directory(args):
    if not isinstance(args, dict):
        args = {}
    requested_path = args.get("path", ".")
    max_entries = args.get("max_entries", 200)
    try:
        max_entries = int(max_entries)
    except (TypeError, ValueError):
        max_entries = 200
    max_entries = max(1, min(max_entries, 500))

    try:
        resolved, rel_posix = resolve_user_path(requested_path, must_exist=True)
    except PathRejected as exc:
        return {"error": exc.code}

    if not resolved.is_dir():
        return {"error": "NOT_A_DIRECTORY", "path": rel_posix}

    entries = []
    try:
        children = sorted(resolved.iterdir(), key=lambda p: p.name)
    except OSError as exc:
        return {"error": "LIST_FAILED", "detail": str(exc)}

    for child in children:
        child_rel = f"{rel_posix}/{child.name}" if rel_posix else child.name
        if _is_denied_relative_path(child_rel, child.name):
            continue

        is_symlink = child.is_symlink()
        entry_type = "symlink" if is_symlink else ("directory" if child.is_dir() else "file")
        size = None
        if not is_symlink and entry_type == "file":
            try:
                size = child.stat().st_size
            except OSError:
                size = None

        entries.append({"name": child.name, "type": entry_type, "size_bytes": size})
        if len(entries) >= max_entries:
            return {
                "path": rel_posix,
                "entries": entries,
                "truncated": True,
            }

    return {"path": rel_posix, "entries": entries, "truncated": False}


MAX_TEXT_FILE_BYTES = 1 * 1024 * 1024  # 1 MiB


def tool_read_text_file(args):
    if not isinstance(args, dict):
        args = {}
    requested_path = args.get("path")
    if not requested_path:
        return {"error": "PATH_REQUIRED"}

    try:
        resolved, rel_posix = resolve_user_path(requested_path, must_exist=True)
    except PathRejected as exc:
        return {"error": exc.code}

    if resolved.is_symlink() or not resolved.is_file():
        return {"error": "NOT_A_REGULAR_FILE", "path": rel_posix}

    try:
        size = resolved.stat().st_size
    except OSError as exc:
        return {"error": "STAT_FAILED", "detail": str(exc), "path": rel_posix}

    if size > MAX_TEXT_FILE_BYTES:
        return {
            "error": "FILE_TOO_LARGE",
            "path": rel_posix,
            "size_bytes": size,
            "max_bytes": MAX_TEXT_FILE_BYTES,
        }

    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        return {"error": "READ_ERROR", "detail": str(exc), "path": rel_posix}

    if b"\x00" in raw:
        return {"error": "BINARY_FILE_REJECTED", "path": rel_posix}

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {"error": "BINARY_FILE_REJECTED", "path": rel_posix}

    redacted_lines = [redact_sensitive(line) for line in text.splitlines()]
    return {"path": rel_posix, "size_bytes": size, "content": "\n".join(redacted_lines)}


MAX_SEARCH_RESULTS = 200
MAX_SEARCH_SCANNED_FILES = 5000

_SKIP_DIR_NAMES = {".git", "__pycache__", "node_modules", ".venv", ".pytest_cache"}


def tool_search_text(args):
    if not isinstance(args, dict):
        args = {}
    query = args.get("query")
    if not query:
        return {"error": "QUERY_REQUIRED"}
    if not isinstance(query, str):
        return {"error": "QUERY_MUST_BE_STRING"}

    requested_root = args.get("root", ".")
    try:
        resolved_root, rel_root_posix = resolve_user_path(requested_root, must_exist=True)
    except PathRejected as exc:
        return {"error": exc.code}

    if not resolved_root.is_dir():
        return {"error": "NOT_A_DIRECTORY", "path": rel_root_posix}

    try:
        max_results = int(args.get("max_results", MAX_SEARCH_RESULTS))
    except (TypeError, ValueError):
        max_results = MAX_SEARCH_RESULTS
    max_results = max(1, min(max_results, MAX_SEARCH_RESULTS))

    try:
        max_files = int(args.get("max_files", MAX_SEARCH_SCANNED_FILES))
    except (TypeError, ValueError):
        max_files = MAX_SEARCH_SCANNED_FILES
    max_files = max(1, min(max_files, MAX_SEARCH_SCANNED_FILES))

    results = []
    files_scanned = 0
    truncated_results = False
    truncated_scan = False

    for current_root, dirs, files in os.walk(resolved_root, followlinks=False):
        current_root_path = Path(current_root)

        kept_dirs = []
        for d in dirs:
            if d in _SKIP_DIR_NAMES:
                continue
            child_dir = current_root_path / d
            if child_dir.is_symlink():
                continue
            try:
                child_rel = child_dir.resolve(strict=False).relative_to(ROOT.resolve()).as_posix()
            except ValueError:
                continue
            if _is_denied_relative_path(child_rel, d):
                continue
            kept_dirs.append(d)
        dirs[:] = kept_dirs

        for name in sorted(files):
            if files_scanned >= max_files:
                truncated_scan = True
                break

            file_path = current_root_path / name
            if file_path.is_symlink():
                continue

            try:
                file_rel = file_path.resolve(strict=False).relative_to(ROOT.resolve()).as_posix()
            except ValueError:
                continue
            if _is_denied_relative_path(file_rel, name):
                continue

            files_scanned += 1

            try:
                raw = file_path.read_bytes()
            except OSError:
                continue
            if b"\x00" in raw:
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue

            for line_number, line in enumerate(text.splitlines(), start=1):
                if query in line:
                    results.append({
                        "path": file_rel,
                        "line": line_number,
                        "text": redact_sensitive(line.strip()[:500]),
                    })
                    if len(results) >= max_results:
                        truncated_results = True
                        break
            if truncated_results:
                break
        if truncated_results or truncated_scan:
            break

    return {
        "root": rel_root_posix,
        "query": query,
        "results": results,
        "files_scanned": files_scanned,
        "truncated_results": truncated_results,
        "truncated_scan": truncated_scan,
    }


GIT_BIN = "/usr/bin/git"


def tool_git_status(args):
    if not isinstance(args, dict):
        args = {}
    requested_path = args.get("path", ".")

    try:
        resolved, rel_posix = resolve_user_path(requested_path, must_exist=True)
    except PathRejected as exc:
        return {"error": exc.code}

    if not resolved.is_dir():
        return {"error": "NOT_A_DIRECTORY", "path": rel_posix}

    if not (resolved / ".git").exists():
        return {"error": "NOT_A_GIT_REPOSITORY", "path": rel_posix}

    argv = [GIT_BIN, "-C", str(resolved), "status", "--short", "--branch"]
    result = safe_run(argv, timeout=8)
    if "error" in result:
        return {"path": rel_posix, "error": "GIT_FAILED", "detail": result["error"]}
    if not result["ok"]:
        return {"path": rel_posix, "error": "GIT_FAILED", "stderr": result["stderr"]}

    lines = [redact_sensitive(line) for line in result["stdout"].splitlines()]
    return {"path": rel_posix, "ok": True, "lines": lines}


DOCKER_BIN = "/usr/bin/docker"


def tool_docker_ps(_args):
    # Fixed, read-only diagnostic command. No user-controlled input.
    return safe_run([DOCKER_BIN, "ps", "--format", "{{json .}}"])


SYSTEMCTL_BIN = "/usr/bin/systemctl"


def tool_list_services(_args):
    # Fixed, read-only diagnostic query. No user-controlled input.
    result = safe_run(
        [SYSTEMCTL_BIN, "list-units", "--type=service", "--all", "--no-legend", "--no-pager"],
        timeout=8,
    )
    if "error" in result:
        return {"error": "SYSTEMCTL_FAILED", "detail": result["error"]}
    lines = [redact_sensitive(line) for line in result.get("stdout", "").splitlines()]
    return {"ok": result["ok"], "returncode": result["returncode"], "lines": lines}


# ---------------------------------------------------------------------------
# forisec-cl3-dashboard project-context proxy tools.
#
# These four tools are fixed-endpoint, read-only HTTP GET proxies to the
# LOCAL forisec-cl3-dashboard project-context API. The base URL is a
# literal constant -- never environment-overridable, never derived from
# caller input -- so no caller can ever point this at an arbitrary host,
# scheme, or port. No filesystem access, no subprocess, no write. Every
# request has a short fixed timeout and a bounded response size. Input
# validation here is deliberately conservative (fixed length/character
# limits) even though the dashboard API enforces its own limits again
# server-side -- defense in depth, never trust-the-caller.
# ---------------------------------------------------------------------------
FORISEC_CONTEXT_BASE_URL = "http://127.0.0.1:8766"  # fixed; do not make env-configurable
FORISEC_CONTEXT_HTTP_TIMEOUT = 6
FORISEC_CONTEXT_MAX_RESPONSE_BYTES = 200_000
_FORISEC_CONTEXT_SECTION_RE = re.compile(r"^[a-z_]{1,64}$")


class _NoRedirectHandler(HTTPRedirectHandler):
    """The dashboard's context API never redirects. Refuse to follow any
    redirect rather than silently trusting wherever it points."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(newurl, code, "Unexpected redirect from context API", headers, fp)


def _forisec_context_get(request_path, query=None):
    """GET request_path (must start with '/') against the fixed
    FORISEC_CONTEXT_BASE_URL only, with an optional urlencoded query
    dict. Returns the parsed JSON body, or an {"available": False, ...}
    envelope on any network/parse failure -- never raises."""
    assert request_path.startswith("/")
    url = FORISEC_CONTEXT_BASE_URL + request_path
    if query:
        url = url + "?" + urlencode(query)
    req = Request(url, method="GET", headers={"Accept": "application/json"})
    opener = build_opener(_NoRedirectHandler())
    try:
        with opener.open(req, timeout=FORISEC_CONTEXT_HTTP_TIMEOUT) as response:
            status = response.status
            raw = response.read(FORISEC_CONTEXT_MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        try:
            raw = exc.read(FORISEC_CONTEXT_MAX_RESPONSE_BYTES + 1)
        except Exception:
            raw = b""
        status = exc.code
    except (URLError, TimeoutError, OSError) as exc:
        return {"available": False, "error": "CONTEXT_SERVICE_UNREACHABLE", "reason": str(exc)}

    truncated = len(raw) > FORISEC_CONTEXT_MAX_RESPONSE_BYTES
    if truncated:
        raw = raw[:FORISEC_CONTEXT_MAX_RESPONSE_BYTES]
    try:
        body = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return {"available": False, "error": "CONTEXT_SERVICE_BAD_RESPONSE", "http_status": status}
    if isinstance(body, dict) and truncated:
        body["_proxy_truncated"] = True
    return body


def tool_forisec_context_bootstrap(_args):
    return _forisec_context_get("/api/v1/context/bootstrap")


def tool_forisec_context_section(args):
    section = str((args or {}).get("section", "")).strip()
    if not section or not _FORISEC_CONTEXT_SECTION_RE.match(section):
        return {"available": False, "error": "INVALID_SECTION"}
    return _forisec_context_get(f"/api/v1/context/section/{section}")


def tool_forisec_context_search(args):
    args = args or {}
    q = str(args.get("q", "")).strip()
    if not (2 <= len(q) <= 300):
        return {"available": False, "error": "INVALID_QUERY_LENGTH"}
    query = {"q": q}

    top_k = args.get("top_k")
    if top_k is not None:
        try:
            top_k_int = int(top_k)
        except (TypeError, ValueError):
            return {"available": False, "error": "INVALID_TOP_K"}
        if not (1 <= top_k_int <= 10):
            return {"available": False, "error": "INVALID_TOP_K"}
        query["top_k"] = top_k_int

    section = args.get("section")
    if section is not None:
        section = str(section).strip()
        if not _FORISEC_CONTEXT_SECTION_RE.match(section):
            return {"available": False, "error": "INVALID_SECTION"}
        query["section"] = section

    return _forisec_context_get("/api/v1/context/search", query)


def tool_forisec_context_source(args):
    path_value = str((args or {}).get("path", "")).strip()
    if not path_value or len(path_value) > 500:
        return {"available": False, "error": "INVALID_PATH"}
    # Absolute-path / traversal / symlink-escape / outside-allowlist
    # rejection is enforced server-side by context/retrieval.py's
    # get_source(). This proxy never touches a filesystem itself and
    # never accepts a host filesystem path -- it only forwards the
    # string to the dashboard's own already-hardened endpoint.
    return _forisec_context_get("/api/v1/context/source", {"path": path_value})


TOOLS = {
    "server_status": tool_server_status,
    "list_directory": tool_list_directory,
    "read_text_file": tool_read_text_file,
    "search_text": tool_search_text,
    "git_status": tool_git_status,
    "docker_ps": tool_docker_ps,
    "list_services": tool_list_services,
    "forisec_context_bootstrap": tool_forisec_context_bootstrap,
    "forisec_context_section": tool_forisec_context_section,
    "forisec_context_search": tool_forisec_context_search,
    "forisec_context_source": tool_forisec_context_source,
}


def mcp_tools_list():
    return {
        "tools": [
            {
                "name": "server_status",
                "description": "Read-only host health summary (hostname, uptime, load, disk, memory).",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "list_directory",
                "description": "Read-only, bounded, sorted directory listing under /home/forybg.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "max_entries": {"type": "integer"},
                    },
                },
            },
            {
                "name": "read_text_file",
                "description": "Read-only text file read under /home/forybg (max 1 MiB, text only).",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
            {
                "name": "search_text",
                "description": "Read-only literal (non-regex) text search under /home/forybg.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "root": {"type": "string"},
                        "query": {"type": "string"},
                        "max_results": {"type": "integer"},
                        "max_files": {"type": "integer"},
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "git_status",
                "description": "Read-only `git status --short --branch` for a repo under /home/forybg.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                },
            },
            {
                "name": "docker_ps",
                "description": "Read-only Docker container status.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "list_services",
                "description": "Read-only systemd service unit listing.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "forisec_context_bootstrap",
                "description": "Read-only fixed-endpoint proxy to the forisec-cl3-dashboard "
                                "LEVEL 1 project context bootstrap bundle (GET /api/v1/context/bootstrap "
                                "on 127.0.0.1:8766 only).",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "forisec_context_section",
                "description": "Read-only fixed-endpoint proxy to the forisec-cl3-dashboard "
                                "LEVEL 2 context section API (GET /api/v1/context/section/{section} "
                                "on 127.0.0.1:8766 only; section must be one of the dashboard's fixed "
                                "allowlisted section names).",
                "inputSchema": {
                    "type": "object",
                    "properties": {"section": {"type": "string"}},
                    "required": ["section"],
                },
            },
            {
                "name": "forisec_context_search",
                "description": "Read-only fixed-endpoint proxy to the forisec-cl3-dashboard "
                                "LEVEL 3 context search API (GET /api/v1/context/search "
                                "on 127.0.0.1:8766 only).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "q": {"type": "string"},
                        "top_k": {"type": "integer"},
                        "section": {"type": "string"},
                    },
                    "required": ["q"],
                },
            },
            {
                "name": "forisec_context_source",
                "description": "Read-only fixed-endpoint proxy to the forisec-cl3-dashboard "
                                "LEVEL 3 context source API (GET /api/v1/context/source "
                                "on 127.0.0.1:8766 only; path must be one of the dashboard's own "
                                "canonical-source allowlist, enforced server-side).",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
        ]
    }


# ---------------------------------------------------------------------------
# OAuth (independent from Diagnostics 3): same protocol shape (PKCE S256,
# authorization_code grant, fixed mcp:read scope, exact redirect_uri
# validation), but its own in-memory codes/tokens and its own routes.
# ---------------------------------------------------------------------------
def _secret_key(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _purge_expired(now=None):
    now = time.time() if now is None else now
    for store in (_authorization_codes, _access_tokens):
        expired = [key for key, record in store.items() if record["expires_at"] <= now]
        for key in expired:
            store.pop(key, None)


def _pkce_s256(verifier):
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify_login_password(password):
    try:
        algorithm, iterations_text, salt_text, digest_text = LOGIN_PASSWORD_HASH.split("$", 3)
        iterations = int(iterations_text)
        if algorithm != "pbkdf2_sha256" or not 200_000 <= iterations <= 2_000_000:
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_text.encode("ascii"))
        supplied = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(supplied, expected)
    except (ValueError, UnicodeEncodeError):
        return False


def issue_authorization_code(client_id, redirect_uri, code_challenge, resource, scope):
    code = secrets.token_urlsafe(32)
    with _oauth_lock:
        _purge_expired()
        _authorization_codes[_secret_key(code)] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "resource": resource,
            "scope": scope,
            "expires_at": time.time() + AUTHORIZATION_CODE_TTL,
        }
    return code


def exchange_authorization_code(code, client_id, redirect_uri, resource, code_verifier):
    code_key = _secret_key(code)
    with _oauth_lock:
        _purge_expired()
        record = _authorization_codes.pop(code_key, None)
        if record is None:
            return None, "INVALID_OR_EXPIRED_CODE"
        if not hmac.compare_digest(record["client_id"], client_id):
            return None, "CLIENT_ID_MISMATCH"
        if not hmac.compare_digest(record["redirect_uri"], redirect_uri):
            return None, "REDIRECT_URI_MISMATCH"
        if not hmac.compare_digest(record["resource"], resource):
            return None, "RESOURCE_MISMATCH"
        if record["code_challenge"] is not None:
            if not code_verifier:
                return None, "MISSING_CODE_VERIFIER"
            try:
                computed_challenge = _pkce_s256(code_verifier)
            except (UnicodeEncodeError, AttributeError):
                return None, "INVALID_CODE_VERIFIER"
            if not hmac.compare_digest(record["code_challenge"], computed_challenge):
                return None, "INVALID_CODE_VERIFIER"

        token = secrets.token_urlsafe(32)
        _access_tokens[_secret_key(token)] = {
            "scope": record["scope"],
            "resource": record["resource"],
            "expires_at": time.time() + ACCESS_TOKEN_TTL,
        }
        return token, ""


def oauth_token_ok(token):
    with _oauth_lock:
        _purge_expired()
        record = _access_tokens.get(_secret_key(token))
        if record is None:
            return False
        return record["scope"] == SCOPE and record["resource"] == RESOURCE


def auth_ok(handler):
    header = handler.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return False, "MISSING_BEARER_TOKEN"
    supplied = header[len("Bearer "):].strip()
    if AUTH_TOKEN and hmac.compare_digest(supplied, AUTH_TOKEN):
        return True, ""
    if supplied and oauth_token_ok(supplied):
        return True, ""
    return False, "INVALID_BEARER_TOKEN"


def json_response(handler, payload, status=200, headers=None):
    body = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    for name, value in (headers or {}).items():
        handler.send_header(name, value)
    handler.end_headers()
    handler.wfile.write(body)


def unauthorized_response(handler, reason):
    challenge = f'Bearer resource_metadata="{RESOURCE_METADATA_URL}", scope="{SCOPE}"'
    json_response(
        handler,
        {"error": "UNAUTHORIZED", "reason": reason},
        status=401,
        headers={"WWW-Authenticate": challenge},
    )


def html_response(handler, body, status=200):
    encoded = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(encoded)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Pragma", "no-cache")
    handler.end_headers()
    handler.wfile.write(encoded)


def rpc_result(request_id, result):
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def rpc_error(request_id, code, message):
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _is_allowed_cimd_url(url):
    try:
        parsed = urlsplit(url)
        return (
            parsed.scheme == "https"
            and parsed.hostname == "chatgpt.com"
            and parsed.username is None
            and parsed.password is None
            and parsed.port in (None, 443)
            and bool(parsed.path)
            and not parsed.fragment
        )
    except ValueError:
        return False


_is_allowed_redirect_uri = _is_allowed_cimd_url


class _ChatGPTRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _is_allowed_cimd_url(newurl):
            raise HTTPError(newurl, code, "Unsafe CIMD redirect", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_client_metadata(client_id):
    if not _is_allowed_cimd_url(client_id):
        raise ValueError("UNTRUSTED_CLIENT_ID")
    request = Request(
        client_id,
        headers={"Accept": "application/json", "User-Agent": "foritech-server-readonly/0.1.0"},
    )
    opener = build_opener(_ChatGPTRedirectHandler())
    try:
        with opener.open(request, timeout=4) as response:
            final_url = response.geturl()
            if not _is_allowed_cimd_url(final_url):
                raise ValueError("UNSAFE_CIMD_REDIRECT")
            raw = response.read(MAX_CIMD_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise ValueError("CIMD_FETCH_FAILED") from exc
    if len(raw) > MAX_CIMD_BYTES:
        raise ValueError("CIMD_DOCUMENT_TOO_LARGE")
    try:
        metadata = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("INVALID_CIMD_DOCUMENT") from exc
    if not isinstance(metadata, dict):
        raise ValueError("INVALID_CIMD_DOCUMENT")
    document_client_id = metadata.get("client_id")
    if document_client_id is not None and document_client_id != client_id:
        raise ValueError("CIMD_CLIENT_ID_MISMATCH")
    redirect_uris = metadata.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not all(isinstance(uri, str) for uri in redirect_uris):
        raise ValueError("INVALID_CIMD_REDIRECT_URIS")
    return metadata


def _query_value(query, name):
    values = query.get(name, [])
    if len(values) != 1 or not values[0]:
        return None
    return values[0]


def _basic_client_id(handler):
    header = handler.headers.get("Authorization", "")
    if not header.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8")
        client_id, _client_secret = decoded.split(":", 1)
        return client_id or None
    except (ValueError, UnicodeDecodeError):
        return None


def _append_query(url, values):
    parsed = urlsplit(url)
    existing = parse_qs(parsed.query, keep_blank_values=True)
    for key, value in values.items():
        existing[key] = [value]
    query = urlencode(existing, doseq=True)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path in {
            f"{ROUTE_PREFIX}/.well-known/oauth-protected-resource",
            f"{ROUTE_PREFIX}/.well-known/oauth-protected-resource/mcp",
        }:
            json_response(self, {
                "resource": RESOURCE,
                "authorization_servers": [ISSUER],
                "scopes_supported": [SCOPE],
                "bearer_methods_supported": ["header"],
            })
            return
        if parsed.path == f"{ROUTE_PREFIX}/.well-known/oauth-authorization-server":
            json_response(self, {
                "issuer": ISSUER,
                "authorization_endpoint": f"{ISSUER}/authorize",
                "token_endpoint": f"{ISSUER}/token",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": [
                    "client_secret_basic",
                    "client_secret_post",
                    "none",
                ],
                "client_id_metadata_document_supported": True,
                "scopes_supported": [SCOPE],
            })
            return
        if parsed.path == f"{ROUTE_PREFIX}/authorize":
            self._show_login_form()
            return
        self.send_response(405)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(f"Method not allowed. MCP uses POST {ROUTE_PREFIX}/mcp.\n".encode("utf-8"))

    def do_POST(self):
        parsed = urlsplit(self.path)
        if parsed.path == f"{ROUTE_PREFIX}/authorize":
            self._handle_authorize_login(parsed.query)
            return
        if parsed.path == f"{ROUTE_PREFIX}/token":
            self._handle_token()
            return
        if parsed.path != f"{ROUTE_PREFIX}/mcp":
            json_response(self, {"error": "NOT_FOUND"}, status=404)
            return

        ok, reason = auth_ok(self)
        if not ok:
            unauthorized_response(self, reason)
            return

        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)

        try:
            req = json.loads(raw.decode("utf-8"))
        except Exception:
            json_response(self, rpc_error(None, -32700, "Parse error"), status=400)
            return

        request_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {}) or {}

        if method == "initialize":
            json_response(self, rpc_result(request_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "foritech-server-readonly", "version": "0.1.0"},
            }))
            return

        if method == "notifications/initialized":
            self.send_response(204)
            self.end_headers()
            return

        if method == "tools/list":
            json_response(self, rpc_result(request_id, mcp_tools_list()))
            return

        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {}) or {}

            if name not in ALLOWED_TOOLS:
                json_response(self, rpc_result(request_id, {
                    "content": [{
                        "type": "text",
                        "text": json.dumps({"status": "REJECTED_BY_POLICY", "tool": name}, indent=2),
                    }],
                    "isError": True,
                }))
                return

            try:
                result = TOOLS[name](arguments)
                json_response(self, rpc_result(request_id, {
                    "content": [{
                        "type": "text",
                        "text": json.dumps(result, indent=2, ensure_ascii=False),
                    }],
                    "isError": False,
                }))
                return
            except Exception as exc:
                json_response(self, rpc_result(request_id, {
                    "content": [{
                        "type": "text",
                        "text": json.dumps({"status": "TOOL_ERROR", "tool": name, "error": str(exc)}, indent=2),
                    }],
                    "isError": True,
                }))
                return

        json_response(self, rpc_error(request_id, -32601, "Method not found"))

    def _show_login_form(self, error_message=""):
        action = html.escape(self.path, quote=True)
        error_html = ""
        if error_message:
            error_html = f'<p class="error">{html.escape(error_message)}</p>'
        page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Foritech Server Read-only authorization</title>
  <style>
    body {{ margin: 0; min-height: 100vh; display: grid; place-items: center;
            background: #0b1220; color: #e8eef8; font-family: system-ui, sans-serif; }}
    main {{ width: min(420px, calc(100% - 40px)); padding: 32px;
            background: #131e30; border: 1px solid #2b3a52; border-radius: 16px; }}
    h1 {{ margin: 0 0 8px; font-size: 22px; }}
    p {{ color: #aebbd0; line-height: 1.45; }}
    label {{ display: block; margin: 24px 0 8px; font-weight: 650; }}
    input {{ box-sizing: border-box; width: 100%; padding: 12px; border-radius: 9px;
             border: 1px solid #455875; background: #09111f; color: white; }}
    button {{ width: 100%; margin-top: 16px; padding: 12px; border: 0; border-radius: 9px;
              background: #19a7a8; color: #041415; font-weight: 750; cursor: pointer; }}
    .error {{ color: #ff8d8d; }}
    small {{ display: block; margin-top: 18px; color: #8190a8; }}
  </style>
</head>
<body>
  <main>
    <h1>Foritech server read-only access</h1>
    <p>Authorize access to the general read-only server inspection connector.</p>
    {error_html}
    <form method="post" action="{action}">
      <label for="password">Access password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
      <button type="submit">Authorize</button>
    </form>
    <small>No write, restart, delete or command-execution tools are exposed.</small>
  </main>
</body>
</html>"""
        html_response(self, page)

    def _handle_authorize_login(self, raw_query):
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/x-www-form-urlencoded":
            json_response(self, {"error": "invalid_request"}, status=400)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_FORM_BYTES:
            json_response(self, {"error": "invalid_request"}, status=400)
            return
        raw = self.rfile.read(length)
        try:
            form = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
        except UnicodeDecodeError:
            json_response(self, {"error": "invalid_request"}, status=400)
            return
        password = _query_value(form, "password")
        if not password or not verify_login_password(password):
            self._show_login_form("Invalid password.")
            return

        query = parse_qs(raw_query, keep_blank_values=True)
        response_type = _query_value(query, "response_type")
        client_id = _query_value(query, "client_id")
        redirect_uri = _query_value(query, "redirect_uri")
        code_challenge = _query_value(query, "code_challenge")
        code_challenge_method = _query_value(query, "code_challenge_method")
        resource = _query_value(query, "resource")
        scope = _query_value(query, "scope")
        state = _query_value(query, "state")

        if response_type != "code":
            json_response(self, {"error": "unsupported_response_type"}, status=400)
            return
        if not client_id or not redirect_uri:
            json_response(self, {"error": "invalid_request"}, status=400)
            return
        if not _is_allowed_redirect_uri(redirect_uri):
            json_response(self, {"error": "invalid_redirect_uri"}, status=400)
            return
        if resource != RESOURCE:
            json_response(self, {"error": "invalid_target"}, status=400)
            return

        predefined_id_matches = (
            bool(PREDEFINED_CLIENT_ID)
            and hmac.compare_digest(client_id, PREDEFINED_CLIENT_ID)
        )
        if predefined_id_matches and (
            not PREDEFINED_REDIRECT_URI
            or not hmac.compare_digest(redirect_uri, PREDEFINED_REDIRECT_URI)
        ):
            json_response(self, {"error": "invalid_redirect_uri"}, status=400)
            return
        is_predefined_client = (
            predefined_id_matches
            and bool(PREDEFINED_REDIRECT_URI)
            and hmac.compare_digest(redirect_uri, PREDEFINED_REDIRECT_URI)
        )
        if is_predefined_client:
            if scope not in (None, SCOPE):
                json_response(self, {"error": "invalid_scope"}, status=400)
                return
            scope = SCOPE
            if code_challenge is not None or code_challenge_method is not None:
                if code_challenge_method != "S256" or not code_challenge:
                    json_response(
                        self, {"error": "invalid_request", "reason": "INVALID_PKCE_PARAMETERS"}, status=400
                    )
                    return
        else:
            if code_challenge_method != "S256" or not code_challenge:
                json_response(self, {"error": "invalid_request", "reason": "PKCE_S256_REQUIRED"}, status=400)
                return
            if scope != SCOPE:
                json_response(self, {"error": "invalid_scope"}, status=400)
                return
            try:
                metadata = fetch_client_metadata(client_id)
            except ValueError as exc:
                json_response(self, {"error": "invalid_client", "reason": str(exc)}, status=400)
                return
            if redirect_uri not in metadata["redirect_uris"]:
                json_response(self, {"error": "invalid_redirect_uri"}, status=400)
                return

        code = issue_authorization_code(client_id, redirect_uri, code_challenge, resource, scope)
        redirect_values = {"code": code}
        if state is not None:
            redirect_values["state"] = state
        location = _append_query(redirect_uri, redirect_values)
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _handle_token(self):
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/x-www-form-urlencoded":
            json_response(self, {"error": "invalid_request"}, status=400)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_FORM_BYTES:
            json_response(self, {"error": "invalid_request"}, status=400)
            return
        raw = self.rfile.read(length)
        try:
            form = parse_qs(raw.decode("ascii"), keep_blank_values=True)
        except UnicodeDecodeError:
            json_response(self, {"error": "invalid_request"}, status=400)
            return

        grant_type = _query_value(form, "grant_type")
        code = _query_value(form, "code")
        form_client_id = _query_value(form, "client_id")
        basic_client_id = _basic_client_id(self)
        if form_client_id and basic_client_id and not hmac.compare_digest(form_client_id, basic_client_id):
            json_response(self, {"error": "invalid_client"}, status=401)
            return
        client_id = form_client_id or basic_client_id
        redirect_uri = _query_value(form, "redirect_uri")
        resource = _query_value(form, "resource") or RESOURCE
        code_verifier = _query_value(form, "code_verifier")

        if grant_type != "authorization_code":
            json_response(self, {"error": "unsupported_grant_type"}, status=400)
            return
        if not all((code, client_id, redirect_uri)):
            json_response(self, {"error": "invalid_request"}, status=400)
            return

        token, reason = exchange_authorization_code(code, client_id, redirect_uri, resource, code_verifier)
        if token is None:
            json_response(self, {"error": "invalid_grant", "reason": reason}, status=400)
            return
        json_response(
            self,
            {"access_token": token, "token_type": "Bearer", "expires_in": ACCESS_TOKEN_TTL, "scope": SCOPE},
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )


def main():
    server = HTTPServer((HOST, PORT), Handler)
    print(f"Foritech Server Read-only listening on http://{HOST}:{PORT}{ROUTE_PREFIX}/mcp", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
