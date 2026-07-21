# Foritech Server Read-only

A standalone, read-only MCP diagnostics service for general inspection of
the whole `/home/forybg` tree on `fori-tech-x999`.

This project is **completely separate** from Foritech OS Read-only
Diagnostics 3 (`~/services/foritech-os/server/mcp-readonly/server.py`):

| | Diagnostics 3 (existing, untouched) | Server Read-only (this project) |
|---|---|---|
| Public URL | `https://mcp-readonly.foritech.bg/mcp` | `https://mcp-readonly.foritech.bg/server/mcp` |
| Filesystem root | `/home/forybg/services/foritech-os` | `/home/forybg` |
| Local port | 3110 | 3111 (free at creation time; re-verify before deploy) |
| systemd unit | `foritech-mcp-readonly.service` | `foritech-server-readonly.service` (not installed) |
| OAuth state | its own in-memory codes/tokens | its own, independent in-memory codes/tokens |
| Env file | `/etc/foritech/mcp-readonly.env` | a separate file, e.g. `/etc/foritech/server-readonly.env` |

No code, secrets, or in-memory state is shared between the two. Both can
run side by side under the same Caddy hostname because Caddy routes by
path prefix (`/server/*` vs. everything else) to two different local
ports.

## Tools (read-only only)

1. `server_status` — hostname, uptime, load average, disk usage, memory usage.
2. `list_directory` — bounded (max 500), sorted listing of a directory under `/home/forybg`.
3. `read_text_file` — reads a text file under `/home/forybg`, max 1 MiB, rejects binaries and symlinks.
4. `search_text` — literal (non-regex) substring search under `/home/forybg`, max 200 results, max 5000 scanned files, implemented in pure Python (no shell/subprocess).
5. `git_status` — `git status --short --branch` for a repo under `/home/forybg`, fixed argv, `shell=False`.
6. `docker_ps` — fixed `docker ps --format '{{json .}}'`, `shell=False`.
7. `list_services` — fixed `systemctl list-units --type=service --all --no-legend --no-pager`, `shell=False`.

No write, edit, delete, move, create-directory, restart, stop, chmod,
chown, sudo, or arbitrary-command tool is exposed. See `policy.json` for
the authoritative allow/forbid lists.

## Path security

Every user-supplied path is validated by `resolve_user_path()` in
`server.py` before any filesystem access:

- empty/relative-only input (absolute paths and `~` are rejected)
- no `..` traversal segments
- resolved path must remain under `/home/forybg`
- symlinks are rejected outright (the entry itself, not just what it points to)
- a fixed sensitive-path denylist is checked (see below) — matches return
  `ACCESS_DENIED` whether or not the path exists, so existence of
  sensitive files is never confirmed

### Denylist

Denied directories (anywhere in the path): `.ssh`, `.gnupg`, `.aws`,
`.azure`, `.kube`, `.password-store`, `.local/share/keyrings`.

Denied files (exact): `.git-credentials`, `.netrc`, `.docker/config.json`.

Denied file patterns (case-insensitive): `.env` and `.env.*` (except
`.env.example`, which is explicitly allowed), `*.pem`, `*.key`, `*.p12`,
`*.pfx`, `id_rsa*`, `id_ed25519*`, `*secret*`, `*credentials*`.

Denied entries never appear in `list_directory` output and are never
descended into by `search_text`. `redact_sensitive()` is additionally
applied to every line this service ever returns (search results, file
contents, log/command output) as defense in depth.

## OAuth

Independent PKCE-S256 authorization_code flow, modeled on Diagnostics 3's
implementation for consistency, but with its own state:

- own in-memory `_authorization_codes` / `_access_tokens` (module-level,
  not shared with any other process or file)
- exact `redirect_uri` string match, fixed `mcp:read` scope, no write scope ever
- credentials (bearer token, login password hash, predefined client id/redirect)
  are read only from environment variables at process start — see
  `.env.example`. **No secret values are stored in this repository.**

**Token persistence:** all authorization codes and access tokens live in
a Python dict in this process's memory. Restarting
`foritech-server-readonly.service` clears every issued code and token;
clients must re-authorize. Solving persistence (e.g. a token store) is
explicitly out of scope for this task.

## Public endpoint shape (not yet live)

The app expects to be reached with the `/server` prefix preserved end to
end:

- `POST https://mcp-readonly.foritech.bg/server/mcp`
- `GET/POST https://mcp-readonly.foritech.bg/server/authorize`
- `POST https://mcp-readonly.foritech.bg/server/token`
- `GET https://mcp-readonly.foritech.bg/server/.well-known/oauth-protected-resource`
- `GET https://mcp-readonly.foritech.bg/server/.well-known/oauth-protected-resource/mcp`
- `GET https://mcp-readonly.foritech.bg/server/.well-known/oauth-authorization-server`

These paths are **not confirmed working** until `deploy/Caddyfile.snippet`
is actually applied and tested through Caddy — this task only prepares
the files.

## Manual deployment (not executed by this task)

1. Re-check that port 3111 (or whatever `MCP_SERVER_READONLY_PORT` is set
   to) is still free: `ss -ltn | grep 3111`.
2. Create the real env file (root-owned, 0640, group `forybg`), e.g.:
   `sudo install -m 0640 -o root -g forybg /dev/null /etc/foritech/server-readonly.env`
   then fill in the variables from `.env.example`.
3. Install the unit: `sudo cp deploy/foritech-server-readonly.service /etc/systemd/system/`
4. `sudo systemctl daemon-reload`
5. `sudo systemctl enable --now foritech-server-readonly.service`
6. Confirm it's listening only on localhost: `ss -ltnp | grep 3111`
7. Insert `deploy/Caddyfile.snippet` into `/etc/caddy/Caddyfile` inside the
   existing `mcp-readonly.foritech.bg { ... }` block, **before** the
   existing catch-all `reverse_proxy 127.0.0.1:3110` line.
8. `sudo caddy validate --config /etc/caddy/Caddyfile`
9. `sudo systemctl reload caddy`
10. Test end to end: `curl -s https://mcp-readonly.foritech.bg/server/.well-known/oauth-protected-resource`
    and confirm `/mcp`, `/authorize`, `/token` on the existing Diagnostics 3
    route are unaffected.

## Tests

```
cd ~/services/foritech-server-readonly
python3 -m unittest discover -s tests -v
```

Covers OAuth (PKCE, redirect validation, tool allowlist), the seven
read-only tools (directory listing, text reading, literal search, git
status, output limits), and the security boundary (path traversal,
absolute paths, symlinks, binaries, sensitive-path denial, `.env` vs
`.env.example`, no arbitrary commands, `shell=False` everywhere, policy
completeness, and a hash-based guarantee that Diagnostics 3's files were
not touched).
