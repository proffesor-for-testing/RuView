# RuView Application Security Audit

**Scope:** Application source code, authentication, authorization, cryptography,
input validation, and hardware/network boundaries. Excludes dependency CVEs.
**Date:** 2026-04-28 · **Branch:** `qe-reports` · **Auditor:** qe-security-auditor

---

## Executive summary

The Python FastAPI service (`v1/src/app.py`) has a defensible authentication
posture: HS256-pinned JWT, bcrypt password hashing, constant-time-friendly
verification via `passlib`, in-memory token blacklist, sliding-window rate
limiting with proxy-aware client identification, security headers, and
documented OTA bearer-token auth on the firmware. Hardcoded secrets are
absent from tracked source — the only `.env` is `example.env`, which contains
exclusively placeholders, and `.gitignore` correctly excludes `.env`,
`sdkconfig`, NVS binaries, and CSV credential dumps.

However, the Rust **`wifi-densepose-sensing-server`** binary that ships in
`rust-port/...` and is the canonical runtime today exposes **53 HTTP routes
on `0.0.0.0` with zero authentication**, including write/destructive
endpoints (model load, recording start/delete, training start, calibration,
SONA activate). Combined with an exploitable **path-traversal** in
`download_recording`/`delete_recording`, an attacker on the same
LAN — including any guest WiFi client — can read or delete arbitrary files
the service has access to. The ESP32 firmware permits **unauthenticated OTA
overwrites** when no PSK is provisioned (the default for development
images). These are the two highest-impact findings.

Severity counts: **2 Critical, 4 High, 5 Medium, 3 Low.**

---

## 1. Hardcoded secrets / credentials

| ID | Severity | Location | Evidence |
|----|----------|----------|----------|
| S-1 | Low | `v1/test_auth_rate_limit.py:26` | `SECRET_KEY = "your-secret-key-here"` — placeholder string in a manual integration test, not used at runtime. **Not exploitable**, but should be replaced with `os.environ["SECRET_KEY"]` for clarity. |
| S-2 | Info | `v1/tests/unit/conftest.py` | `os.environ.setdefault("SECRET_KEY", "test-secret-key-for-unit-tests-only")` — test-only, scoped to unit tests. Acceptable. |
| S-3 | Info | `rust-port/.../wifi-densepose-desktop/src/commands/provision.rs:470` | `wifi_password: Some("password123".into())` inside `#[cfg(test)] mod tests` — test fixture only. |

`example.env` was inspected end-to-end (lines 1-300+); every value is either a
literal placeholder (`your-secret-key-here-change-for-production`,
`your-redis-password`) or a well-known dev default
(`postgresql://wifi_user:wifi_password@localhost`). `git log --all -G` for
the secret/password/api_key pattern returned only legitimate test fixtures.
No committed `.env`, no AWS/GitHub/JWT tokens, no PEM private keys.

**`v1/src/config/settings.py:29`** correctly declares
`secret_key: str = Field(...)` (required, no default) so the application
fails to start without a real secret. Good.

---

## 2. Authentication & JWT

The Python middleware at `v1/src/middleware/auth.py` and
`v1/src/api/middleware/auth.py` is largely correct.

**Strengths**

- JWT algorithm is **pinned to a single algorithm** read from settings
  (`algorithms=[self.algorithm]` at `v1/src/middleware/auth.py:58,77` and
  `v1/src/api/middleware/auth.py:191`). The `none` algorithm and algorithm
  confusion are not exploitable — `python-jose` rejects mismatching `alg`.
- Default `jwt_algorithm = "HS256"` (`settings.py:30`) and `secret_key`
  required (no default).
- Password hashing via `passlib.CryptContext(schemes=["bcrypt"])`.
- Token expiry enforced and re-checked on every verify
  (`api/middleware/auth.py:203-205`).
- WebSocket auth is **first-message auth** with a 10-second timeout — JWT
  is **not** in the URL (CWE-598 fix), implemented in
  `v1/src/api/routers/stream.py:83-123` and `:197-237`.
- `/auth/logout` (`v1/src/api/routers/auth.py`) blacklists the bearer
  token; the blacklist is consulted inside `verify_token()`
  (`api/middleware/auth.py:194-195`, `middleware/auth.py:60-62`).

**Weaknesses**

| ID | Severity | Finding |
|----|----------|---------|
| A-1 | **High** | **In-memory token blacklist with naive cleanup.** `TokenBlacklist._cleanup_if_needed()` (`v1/src/api/middleware/auth.py:249-256`) calls `self._blacklisted_tokens.clear()` every hour — it does not check token `exp`. A token revoked at minute 59 is silently re-validated at minute 61. Multi-worker (`workers > 1`) deployment loses the blacklist entirely (per-process state). Mitigation: persist to Redis keyed on `jti` with TTL = remaining `exp`. |
| A-2 | Medium | **Two parallel `get_current_user` implementations.** `v1/src/middleware/auth.py:240-285` performs full token verification, but `v1/src/api/dependencies.py:62-109` does **not** validate JWT — it falls back to `request.state.user` set by middleware (line 74) and otherwise raises 401. This works only because the middleware always runs first. If a future refactor wires routes that use the dependency without the middleware, every request will be rejected. Either delete the dead branch or make the dependency genuinely verify the token. |
| A-3 | Low | **`refresh_token` does not check token `exp`.** `v1/src/middleware/auth.py:353-379` calls `verify_token()` which decodes and signs but does not explicitly enforce expiration before issuing a fresh token (the `jose` library does so by default — verified — so this is **not exploitable** against `python-jose`). Documented for clarity. |
| A-4 | Low | No rate limit specifically on `/auth/login`. Attackers can brute-force credentials at the global anonymous rate-limit budget (100/hr default). Add a strict path limit (e.g. `5/min` per IP) like the existing `path_limits` for `/api/v1/pose/calibrate`. |

There is **no** default user, no built-in admin/admin combo. `UserManager`
starts empty (`v1/src/middleware/auth.py:89`).

---

## 3. Authorization gaps

### Python FastAPI app (`v1/src/api/`)

The middleware-level allow/deny lists in `v1/src/api/middleware/auth.py:27-48`
are correctly partitioned. Cross-referenced against router definitions:

| Route | Method | Auth required | Risk |
|-------|--------|---------------|------|
| `/api/v1/pose/current` | GET | No (public_pattern) | Low — read-only pose data |
| `/api/v1/pose/zones/*` | GET | No | Low |
| `/api/v1/pose/activities` | GET | No | Low |
| `/api/v1/pose/stats` | GET | No | Low |
| `/api/v1/pose/analyze` | POST | **Yes** | OK |
| `/api/v1/pose/calibrate` | POST | **Yes** | OK |
| `/api/v1/pose/historical` | POST | **Yes** | OK |
| `/api/v1/stream/start`,`stop`,`broadcast`,`clients` | POST/GET | **Yes** | OK |
| `/api/v1/stream/status` | GET | No | OK |
| `/auth/logout` | POST | Implicit (requires bearer) | OK |

The Python service’s authorization model is sound.

### Rust `wifi-densepose-sensing-server` (`rust-port/.../sensing-server/src/main.rs`)

**THIS IS THE CRITICAL FINDING. There are NO `tower` auth layers, NO
middleware verifying tokens, and NO API key checks on any of the 50+
routes.** The router is built at lines `4734-4818` and applies only a
`SetResponseHeaderLayer` for cache control. Every endpoint below is
reachable without credentials by anything that can route TCP to the
listener (default: `0.0.0.0`):

| Route | Method | Risk |
|-------|--------|------|
| `POST /api/v1/recording/start` | mutating | **High** — anyone can start a recording, fill disk |
| `POST /api/v1/recording/stop` | mutating | **High** — anyone can stop an in-progress capture |
| `DELETE /api/v1/recording/{id}` | destructive | **Critical** — combined with path traversal (see I-1) |
| `GET /api/v1/recording/download/{id}` | read | **Critical** — same path traversal |
| `POST /api/v1/models/load` | mutating | High |
| `POST /api/v1/models/unload` | mutating | High |
| `DELETE /api/v1/models/{id}` | destructive | Medium (sanitized via `Path::file_name`) |
| `POST /api/v1/models/lora/activate` | mutating | High |
| `POST /api/v1/model/sona/activate` | mutating | High |
| `POST /api/v1/train/start`,`stop`,`pretrain`,`lora` | mutating | High |
| `POST /api/v1/adaptive/train`,`unload` | mutating | High |
| `POST /api/v1/calibration/start`,`stop` | mutating | High |

| ID | Severity | Finding |
|----|----------|---------|
| Z-1 | **Critical** | All mutating/destructive Axum routes in `wifi-densepose-sensing-server/src/main.rs:4750-4818` and `recording.rs:432-442`, `model_manager.rs:444-455`, `training_api.rs:1712-1718` lack any authentication layer. An attacker on the same LAN (or anyone if the service is exposed) can stop sensing, delete recordings, swap models, or trigger arbitrary training runs. **Remediation:** add `axum::middleware::from_fn` that validates a bearer token (HMAC or PSK), and split the router into `public_app` and `auth_app`. The `OTA_NVS_KEY` PSK pattern from `firmware/esp32-csi-node/main/ota_update.c:64-72` is a good template (constant-time compare). |
| Z-2 | Low | No CORS layer is registered on the Rust server (only `Cache-Control`). Browsers will block cross-origin POSTs by default, but raw HTTP clients are unaffected. Once auth lands, add an explicit CORS allowlist. |

---

## 4. Cryptography

No use of MD5/SHA1/DES/RC4/ECB was found in security-sensitive paths.
Searches across `v1/src` and the Rust `signal/`, `api/`, `hardware/`,
`sensing-server/` crates returned no hits.

| ID | Severity | Finding |
|----|----------|---------|
| C-1 | Info | RVF firmware payload integrity uses Ed25519 signatures (`firmware/esp32-csi-node/main/rvf_parser.c:171`, `wasm_upload.c:129`) with a build-hash check first (`rvf_parser.c:135`). Default-on (`wasm_verify = 1` at `nvs_config.c:89`); only disabled if Kconfig explicitly does so. Good. |
| C-2 | Info | OTA PSK comparison is constant-time XOR loop (`firmware/esp32-csi-node/main/ota_update.c:64-72`). Good. |
| C-3 | Low | Mesh control messages can be sent with `RV_AUTH_NONE` (CRC only) per `firmware/.../rv_mesh.h:57`. ADR-032 (proposed) addresses this. Documented. |

No custom cryptographic primitives are rolled by hand; ESP-IDF and `python-jose`/`passlib`/`ring`/`sha2` handle the heavy lifting.

---

## 5. Input validation & injection

### SQL injection

The Rust DB crate `wifi-densepose-db/src/lib.rs` is a 1-line stub — there
are no SQL queries to attack. `v1/src/services/` and other Python sources
showed **zero** instances of `cursor.execute(f"...")`,
`.execute("..." + var)`, or `.format(...)` SQL — all queries use
SQLAlchemy ORM (`select(...).where(...)`, e.g. `tasks/backup.py:313-318`).
**No SQL injection found.**

### Command injection

| ID | Severity | Finding |
|----|----------|---------|
| I-1 | Medium | `v1/src/sensing/rssi_collector.py:285,548,582` and `674,713` invoke `subprocess.run(...)` and `subprocess.Popen(...)` with **no `shell=True`** and **list-form argv**. Inputs (`self._interface`) trace back to constructor calls in `tests/integration/...` and `create_collector()` — never to a network/HTTP boundary. `iw dev <iface> station dump` and `netsh wlan show interfaces` are safe under list-form invocation. **Documented as smell, not exploitable.** |
| I-2 | Low | `v1/src/tasks/backup.py:158-162,253-257,405-408` uses `asyncio.create_subprocess_exec(*pg_dump_cmd, env=env, ...)` with explicit argv — host/port/user/db_name come from settings. No shell. Safe. |
| I-3 | Low | `firmware/esp32-csi-node/provision.py:113-117,128-131,153-162` invokes `esptool` and `nvs_partition_gen` via `subprocess.check_call` with list-form argv. The CLI runs locally with operator-supplied args; no untrusted-input path. Safe. |

### Path traversal

| ID | Severity | Finding |
|----|----------|---------|
| **P-1** | **Critical** | **Exploitable path traversal in `wifi-densepose-sensing-server/src/recording.rs`.** Both `download_recording` (line 345-387) and `delete_recording` (line 389-425) take `id: String` from the URL and compose a path via `dir.join(format!("{id}.csi.jsonl"))` (lines 351, 394, 395) **without any sanitization**. `PathBuf::join("../../etc/passwd")` resolves above `RECORDINGS_DIR`. Combined with finding **Z-1** (no auth), any LAN client can: <br>• `GET /api/v1/recording/download/..%2F..%2F..%2Fetc%2Fpasswd` → response body contains `/etc/passwd.csi.jsonl` (the `.csi.jsonl` suffix is appended unconditionally, but if a target file with that exact name exists or can be created elsewhere it is exfiltrated; on Linux, paths like `../../tmp/foo` will resolve and read whatever sits at `/tmp/foo.csi.jsonl`). <br>• `DELETE /api/v1/recording/..%2F..%2F..%2Fhome%2Fuser%2Fmodel` deletes `model.csi.jsonl` and `model.csi.meta.json` if they exist outside the recordings dir. <br>**Remediation:** apply the same sanitization used in `delete_model` at `main.rs:2796-2804`: <br>```rust<br>let safe_id = std::path::Path::new(&id).file_name().and_then(|f| f.to_str()).unwrap_or("");<br>if safe_id.is_empty() || safe_id != id { return error; }<br>``` |
| P-2 | Low | No archive extraction (`tarfile.extractall`, `zipfile.ZipFile`, `shutil.unpack_archive`) is used anywhere in the Python or Rust source. No tar slip risk. |

### XSS / template injection / SSRF

No HTML templating is used (UI is React + JSON APIs). No HTTP client takes a
user-controllable URL — `swarm_bridge.c` posts to a configured `seed_url`
loaded from NVS, not a request body. **None found.**

---

## 6. Hardware / network boundary findings

| ID | Severity | Finding |
|----|----------|---------|
| **H-1** | **Critical** | **ESP32 OTA accepts unauthenticated firmware uploads when no PSK is provisioned.** `firmware/esp32-csi-node/main/ota_update.c:44-49`: `if (s_ota_psk[0] == '\0') return true;` (auth disabled, "permissive for dev"). The PSK is loaded from NVS namespace `security`/`ota_psk` — but the canonical provisioning script `firmware/esp32-csi-node/provision.py` does **not** set this key (no `--ota-psk` flag exists). Therefore every device that ships from `provision.py` boots with OTA auth disabled and accepts a `POST /ota` from any LAN client, replacing firmware on a device with WiFi-CSI access to occupants. **Remediation:** (a) refuse to boot OTA endpoint when PSK is empty unless a `CONFIG_OTA_INSECURE_DEV` Kconfig is set; (b) add `--ota-psk` to `provision.py` and require it for production. |
| H-2 | Medium | **Mesh control plane allows `RV_AUTH_NONE`.** Per `firmware/.../rv_mesh.h:54-60`, control messages can be sent with CRC-only auth. ADR-032 (proposed) addresses this; until merged, an attacker with raw 802.11 control-frame access can inject `RV_MSG_ROLE_ASSIGN` or `RV_MSG_CHANNEL_PLAN`. |
| H-3 | Low | The sensing-server WebSocket `/ws/sensing` is unauthenticated (`main.rs:4735`). Anyone can subscribe to live CSI/pose stream — privacy-relevant since pose data is biometric. Pair with **Z-1** remediation. |
| H-4 | Low | `firmware/.../main.c:116` and `nvs_config.c:115` log WiFi SSID at `ESP_LOGI` level (`%s` format). Password is masked (`***`). SSID is not strictly secret but is a fingerprintable identifier. Consider only logging the first 4 chars. |

---

## 7. Logging hygiene

The Python codebase **passes** the basic hygiene check.
`grep -rn "logger\..*\(token\|password\|secret\|api_key\)"` returned only
one hit (`v1/src/api/dependencies.py:437`), which logs the *fact* that a
token was rejected, not the token itself.

| ID | Severity | Finding |
|----|----------|---------|
| L-1 | Low | `firmware/.../swarm_bridge.c:230` logs `"Bearer token configured for Seed auth"` — message-only, no token value. Acceptable. |
| L-2 | Low | `firmware/.../nvs_config.c:115` logs `ssid=%s`. As H-4. |
| L-3 | Info | No leakage of `Authorization` header values, request bodies, or password fields was found in `print()` or `logger.*` calls. Good. |

---

## Prioritized remediation

### P0 — Fix this sprint

1. **Z-1**: Add bearer-token auth middleware to **all mutating routes** in `wifi-densepose-sensing-server/src/main.rs` (routes at lines 4750-4818). Use the OTA PSK pattern from `ota_update.c:44-72` (constant-time compare). Bind to `127.0.0.1` by default unless `--bind-public` is passed.
2. **P-1**: Sanitize `id` parameter in `recording.rs:345,389` using `Path::file_name()` (mirror of `main.rs:2796-2804` for models). Add an integration test that asserts `id="../etc/passwd"` returns 400.
3. **H-1**: Refuse to register the OTA HTTP handler when `s_ota_psk[0]=='\0'` unless `CONFIG_OTA_INSECURE_DEV=y`. Add `--ota-psk` to `provision.py` and document it in `firmware/esp32-csi-node/README.md`.

### P1 — This quarter

4. **A-1**: Replace in-memory `TokenBlacklist` with a Redis-backed implementation keyed by `jti` and TTL = remaining `exp`. Required before any multi-worker deployment.
5. **A-2**: Either delete `get_current_user` from `v1/src/api/dependencies.py:62-109` and import the one from `middleware/auth.py`, or make it actually verify the JWT. Pick one source of truth.
6. **A-4**: Add `path_limit` of `5/min` per IP for `/auth/login` in `v1/src/api/middleware/rate_limit.py:51-57`.
7. **H-2**: Land ADR-032 (mesh HMAC) — currently proposed.

### P2 — Backlog

8. **S-1**: Replace placeholder `SECRET_KEY` literal in `v1/test_auth_rate_limit.py:26` with `os.environ["SECRET_KEY"]`.
9. **Z-2**: After Z-1 lands, add an explicit CORS allowlist to the Rust sensing-server.
10. **H-4 / L-2**: Reduce ESP32 SSID log verbosity to `LOG_DEBUG` or first-4-chars.

---

**Verification method.** Each finding above was confirmed by reading the
referenced lines (not pattern-matched alone). Suspected false positives
(I-1 subprocess uses, S-2/S-3 test fixtures, A-3 refresh_token) are
explicitly marked as not-exploitable. The Python `app.py` (canonical
entry) and Rust `sensing-server/src/main.rs` (canonical Rust entry) were
both reviewed for middleware composition.
