# RuView — Ultra-Deep Security Audit (Whole Project)

**Date:** 2026-04-28
**Branch:** `qe-reports` @ `110e34f5`
**Scope:** entire repository — application code, supply chain, CI/CD, infrastructure, hardware boundaries
**Method:** three specialised QE security agents run in parallel, non-overlapping scopes; each produced an evidence-grounded sub-report. This document is the consolidated executive view.

This audit was triggered by RuView issue [#442](https://github.com/ruvnet/RuView/issues/442) (Pentesterra/DevGuard scanner) but went well beyond it. **The most severe issues found are not in #442.**

---

## Sub-reports (per-agent detail)

| Agent | Domain | File |
|-------|--------|------|
| `qe-security-scanner` | Supply chain, deps, CI/CD, IaC | [`audit-supply-chain.md`](audit-supply-chain.md) |
| `qe-security-auditor` | Auth, crypto, input validation, hardware boundaries | [`audit-application.md`](audit-application.md) |
| `qe-pentest-validator` | Exploitability proofs + new attack chains | [`audit-exploitability.md`](audit-exploitability.md) |
| Issue triage | Pentesterra DevGuard report verification | [`issue-442-analysis.md`](issue-442-analysis.md) |

---

## TL;DR — what to do this week

| # | Finding | Severity | Effort | Why it matters |
|---|---------|----------|--------|----------------|
| **A** | **Bearer-token-shaped string in git history** — `hyHVY4Ux6uBAh8FaQzF_9OwWCWMFB-YuM2OJ3Dcwdm8`, recoverable via `git log -S` on any clone | **LOW** (per repo owner: testing seed, not a production credential) | 15 min | Verified in commits `2b8a7cc4`/`a4bd2308`. Confirmed with @ruvnet that this was a test seed used during Cognitum Seed development, not a live credential. No rotation needed. Recommendation: still scrub from history at next opportunity to keep scanners quiet, and add a pre-commit hook to prevent future leaks. |
| **B** | **Sensing-server REST API has zero auth on 50+ mutating routes** — pending design-intent confirmation from @ruvnet | CRITICAL (pending review) | 1 day | `wifi-densepose-sensing-server/src/main.rs:4750-4810` builds the Axum router with only a `Cache-Control` layer. May be intentional for a LAN-only device. **Tracked separately**, not in the #442 fix branch. |
| **C** | **Path-traversal in recording APIs** — both `start_recording` (`main.rs:2926-2945`) and `download_recording`/`delete_recording` (`recording.rs:345-425`) join unsanitised `id` into `PathBuf` | CRITICAL (chained with B) | 1 hour | Sibling `delete_model` already does the right thing — pattern just wasn't applied here. PoC: `{"id":"../../../../tmp/PWNED"}`. |
| **D** | **ESP32 OTA fail-open** — `firmware/esp32-csi-node/main/ota_update.c:44-49` returns auth-success when `s_ota_psk` is empty, and `provision.py` has no flag to set the PSK | HIGH | 4 hours | Production-flashed devices accept unauthenticated firmware uploads from any LAN client. |
| **E** | **6 GitHub Actions pinned to mutable `@master`/`@main` refs across `security-scan.yml` + `ci.yml`**, including `snyk/actions/python@master` which has direct `SNYK_TOKEN` access | HIGH | 1 hour | Same supply-chain class that issue #442 raised — but #442 only flagged the lowest-risk one. |
| **F** | **`axios@1.13.6` direct dependency in `ui/mobile/package.json:19` with active SSRF advisory**, plus 24 other npm advisories surfaced by `npm audit` | HIGH | 2 hours | More impactful than the xmldom/node-forge findings in #442 (those are dev-time only). |
| **G** | **`vite@6.4.1` direct devDep in desktop UI** — vulnerable to GHSA-p9ff-h696-f583 (arbitrary file read via dev-server WebSocket) | HIGH | 30 min | Affects developer machines, not production. |

The remaining issues are catalogued below.

---

## 1. Bearer-token-shaped string in git history (LOW — confirmed test seed)

**Source:** `audit-exploitability.md` §NEW-3.

**Verification:**

```bash
$ git log --all -S 'hyHVY4Ux6uBAh8FaQzF' --pretty=format:'%h %ai %s'
a4bd2308  2026-04-02  feat: ADR-069 ESP32 CSI → Cognitum Seed RVF pipeline (v0.5.4-esp32)
2b8a7cc4  2026-03-20  feat: happiness scoring pipeline + ESP32 swarm with Cognitum Seed (#285)
```

**Disposition:** confirmed with @ruvnet (repo owner) that this was a development test seed used during Cognitum Seed pretraining work, not a live production credential. Severity downgraded from CRITICAL to LOW. **No rotation required.**

The static analyser correctly flagged the pattern — both DevGuard (issue #442 was silent on this, but other scanners would catch it) and our internal pentest agent identified it. The pattern-match itself is healthy; the false-positive comes from the lack of context that scanners have about test fixtures.

**Recommended low-priority follow-ups:**

1. **Optional history scrub** — if a future force-push is acceptable, remove the string at the same time:
   ```bash
   git filter-repo --replace-text <(echo 'hyHVY4Ux6uBAh8FaQzF_9OwWCWMFB-YuM2OJ3Dcwdm8==><TEST_SEED_REDACTED>')
   ```
   This keeps third-party scanners quiet on future audits.
2. **Pre-commit `gitleaks` hook** — to catch future *real* credentials before push (CI already scans, but post-commit). This is the more valuable change and is independent of the test seed:
   ```yaml
   # .pre-commit-config.yaml
   repos:
     - repo: https://github.com/gitleaks/gitleaks
       rev: v8.18.0
       hooks: [{ id: gitleaks }]
   ```
3. **Add a `.gitleaksignore`** if scrub is rejected — list this specific commit/finding so scanners don't re-flag it.

---

## 2. Sensing-server: unauthenticated control plane (Critical)

**Sources:** `audit-application.md` §Z-1, `audit-exploitability.md` §NEW-2.

**Evidence** — `rust-port/wifi-densepose-rs/crates/wifi-densepose-sensing-server/src/main.rs:4750-4810`:

```rust
let http_app = Router::new()
    .route("/api/v1/recording/start", post(start_recording))
    .route("/api/v1/recording/{id}", delete(delete_recording))
    .route("/api/v1/recording/{id}/download", get(download_recording))
    .route("/api/v1/models/load", post(load_model))
    .route("/api/v1/train/start", post(start_train))
    .route("/api/v1/calibration/start", post(start_calibration))
    // ... 40+ more
    .layer(SetResponseHeaderLayer::if_not_present(...))  // ← only layer
    .with_state(state);
```

No `tower_http::auth`, no extractor checking a bearer header, no IP-allowlist, no `127.0.0.1` bind. The server defaults to `0.0.0.0`. Anyone on the same network can:
- Start arbitrary recordings (potential surveillance).
- Load arbitrary model paths (RCE if the model loader is permissive).
- Stream live CSI from `/ws/sensing` (privacy breach — CSI can be reduced to coarse pose).
- Mass-delete recordings.

**Fix sketch:**

```rust
let auth = ValidateRequestHeaderLayer::custom(BearerAuth::new(state.config.api_token.clone()));
let mutating = Router::new()
    .route("/api/v1/recording/start", post(start_recording))
    .route("/api/v1/models/load", post(load_model))
    .route("/api/v1/train/start", post(start_train))
    // ...
    .layer(auth);
let public = Router::new()
    .route("/healthz", get(healthz))
    .route("/api/v1/version", get(version));
let app = public.merge(mutating).layer(/* tracing, cors, etc. */);
```

Also bind to `127.0.0.1` by default unless `RV_BIND_ADDR` is explicitly set, and log a startup warning if bound to non-loopback without auth.

---

## 3. Path-traversal in recording APIs (Critical when chained)

**Sources:** `audit-application.md` §P-1, `audit-exploitability.md` §NEW-1.

**Three vulnerable callsites** — all use the same anti-pattern of joining a user-controlled `id` directly:

| File | Line | Symbol |
|------|------|--------|
| `crates/wifi-densepose-sensing-server/src/main.rs` | 2926-2945 | `start_recording` |
| `crates/wifi-densepose-sensing-server/src/recording.rs` | 345-387 | `download_recording` |
| `crates/wifi-densepose-sensing-server/src/recording.rs` | 389-425 | `delete_recording` |

**Sibling code that does it correctly** — `main.rs:2796-2804` (`delete_model`) sanitises with `Path::file_name()`. Apply that pattern uniformly:

```rust
fn safe_id_to_path(dir: &Path, id: &str, ext: &str) -> Result<PathBuf, ApiError> {
    let raw = format!("{id}{ext}");
    let name = Path::new(&raw).file_name()
        .ok_or(ApiError::BadRequest("invalid id"))?;
    Ok(dir.join(name))
}
```

Add a property test that asserts `safe_id_to_path` always returns a path inside `dir.canonicalize()`.

---

## 4. ESP32 OTA fail-open (High)

**Source:** `audit-application.md` §H-1.

**Evidence** — `firmware/esp32-csi-node/main/ota_update.c:44-49`:

```c
static bool ota_authenticate(const char *psk_received) {
    if (s_ota_psk[0] == '\0') {
        ESP_LOGW(TAG, "OTA PSK not provisioned, accepting unauthenticated update");
        return true;  // ← fail-open
    }
    return constant_time_compare(s_ota_psk, psk_received, ...);
}
```

`firmware/esp32-csi-node/provision.py` has no `--ota-psk` flag, so the default state of a freshly-provisioned device is *unauthenticated OTA accept*.

**Fix:**
- Make PSK mandatory in production: refuse OTA registration if `s_ota_psk[0] == '\0'` unless `CONFIG_OTA_INSECURE_DEV=y` is set at build time. Log loud at boot.
- Add `--ota-psk PSK` to `provision.py` and require it unless `--insecure-dev` is also passed.
- Bonus: switch from PSK to Ed25519 firmware signature verification (already used elsewhere per `rvf_parser.c:171`).

---

## 5. Supply chain (consolidates issue #442 + scanner findings)

**Source:** `audit-supply-chain.md`.

### 5.1 GitHub Actions

**~70 `uses:` statements; 7 pinned to mutable refs:**

| File:line | Action | Has secret? |
|-----------|--------|-------------|
| `security-scan.yml:114` | `snyk/actions/python@master` | ✅ `SNYK_TOKEN` |
| `security-scan.yml:166` | `aquasecurity/trivy-action@master` | indirect |
| `security-scan.yml:224` | `bridgecrewio/checkov-action@master` | — |
| `security-scan.yml:241` | `tenable/terrascan-action@main` | — |
| `security-scan.yml:250` | `checkmarx/kics-github-action@master` | — (the one #442 reported) |
| `security-scan.yml:280` | `trufflesecurity/trufflehog@main` | (`GITLEAKS_LICENSE` if used) |
| `ci.yml:258` | `aquasecurity/trivy-action@master` | indirect |

The Snyk one is materially higher risk than the Checkmarx one #442 emphasised — it has direct token access. None of these are pinned to a SHA.

**Fix:** SHA-pin all third-party actions (first-party `actions/*` and `github/*` are lower-risk but should still be SHA-pinned for hygiene). Add `dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule: { interval: weekly }
```

### 5.2 Workflow with auto-write

`update-submodules.yml` runs every 6 hours with `contents: write` + `pull-requests: write`, blindly tracking upstream `main` for three submodules at SHAs `30fe5eb7`, `050c3fe6`, `1210646955`. `vendor/ruvector/` is `COPY`'d straight into `docker/Dockerfile.rust:14` — upstream compromise becomes a production-image compromise within hours.

**Fix:** require human review on submodule update PRs (already happens — but verify the cron-opened PRs aren't auto-merged), or pin to specific tags rather than `main`.

### 5.3 npm advisories

`npm audit` on `ui/mobile/package-lock.json` reports **25 advisories (5 high, 16 moderate, 4 low)**. Highlights from the supply-chain agent:

- `@xmldom/xmldom@0.8.11` — confirmed; affected-range mismatch noted in #442 analysis but bumping to `0.8.13` is cheap insurance.
- `node-forge@1.3.3` — confirmed; bump to `≥1.4.0` via `overrides`.
- `picomatch@2.3.1` — transitive in dev tooling only (anymatch/jest-util/micromatch); cosmetic bump.
- **`axios@1.13.6` — direct dep in `package.json:19`**, active SSRF advisory. Higher impact than the #442 findings.
- `lodash@4.17.23` (CVSS 8.1), `follow-redirects@1.15.11`, `brace-expansion`, `postcss@8.4.49` — bump.

`rust-port/.../wifi-densepose-desktop/ui/package-lock.json` — `vite@6.4.1` direct devDep, GHSA-p9ff-h696-f583 (arbitrary file read), GHSA-4w7w-66w2-5vf9. Dev-server only, but anyone with web access to a developer's machine can grab files.

**Fix template:**

```json
// ui/mobile/package.json
{
  "dependencies": { "axios": "^1.7.7" },
  "overrides": {
    "@xmldom/xmldom": "0.8.13",
    "node-forge": "^1.4.0",
    "picomatch": "^2.3.2"
  }
}
```

### 5.4 Python deps

- `v1/requirements-lock.txt` only pins 4 of the dozens of resolved transitives. `python-jose[cryptography]>=3.3.0` and `passlib[bcrypt]>=1.7.4` allow vulnerable resolutions at build time.
- CI runs `pip-audit` with `continue-on-error: true` — failures are silently swallowed.
- **Fix:** generate a full lock with `pip-tools` and remove `continue-on-error: true` from `pip-audit`/`safety` steps (or at minimum drop the build status to "warn" only when explicitly suppressed).

### 5.5 Rust deps

- All known-bad-pin spot checks (openssl, time, smallvec, hyper, tokio, rustls, chrono) are above their fixed versions — looks healthy.
- **CI gap:** `cargo audit` is **not wired into any workflow.** Add it:

```yaml
- name: cargo audit
  run: |
    cargo install cargo-audit --locked
    cargo audit --deny warnings
  working-directory: rust-port/wifi-densepose-rs
```

### 5.6 Docker

- `docker/docker-compose.yml:8` and `:33` use `:latest` and `:python` (mutable tags).
- Both Dockerfiles run as root (no `USER` directive).
- Base images not digest-pinned.
- **Fix:** pin base images to digests, add `USER 10001:10001` near the end of each Dockerfile, drop unused capabilities in compose.

---

## 6. Auth / authorisation lower-priority items

**Source:** `audit-application.md` §A-1 and §Medium/Low.

- **In-memory `TokenBlacklist`** at `v1/src/api/middleware/auth.py:249-256` — wipes every hour without checking `exp`, lost on multi-worker. Replace with Redis-backed store + per-token TTL.
- **Two parallel `get_current_user` implementations** — `v1/src/api/dependencies.py:62-109` (verifies) vs `v1/src/middleware/auth.py:240-285` (defers). Pick one and delete the other; this is a future-bug magnet.
- **Mesh control-plane `RV_AUTH_NONE`** — already proposed for hardening in ADR-032, accelerate that work.
- **No per-route rate limit on `/auth/login`** — global rate limit may exist; verify and add if not.
- **SSID logged plaintext on ESP32** — bias toward minimising; not a leak per se but unnecessary.

---

## 7. What was clean (worth recording)

This audit also surfaced what's *not* broken — these have evidence backing them:

- **No hardcoded secrets in tracked source.** `example.env` is placeholders only. `.gitignore` excludes `.env`, `sdkconfig`, `nvs_*.bin`, `nvs_*.csv`, `CLAUDE.local.md`. (The single git-history leak in §1 is the exception.)
- **JWT pinned to a single algorithm** (HS256), `secret_key` is a required field.
- **bcrypt password hashing** via `passlib.CryptContext`.
- **WebSocket auth via first-message** (no token in query string).
- **No SQL injection** — SQLAlchemy ORM throughout; Rust DB crate is a stub.
- **No command injection** — every `subprocess` call uses list-form argv, no `shell=True`. Inputs do not cross network boundaries.
- **No archive-extract or SSRF surfaces.**
- **OTA PSK comparison is constant-time** (the bug is the empty-PSK fail-open, not the comparison itself).
- **RVF firmware payloads are Ed25519-signed** by default.
- **Logging hygiene is good** — passwords masked, no Authorization-header logging, no request-body dumps.

---

## 8. Final remediation plan

### Day-1 (must merge this week)

1. SHA-pin the 7 mutable Actions and rotate `SNYK_TOKEN`/`SEMGREP_APP_TOKEN` (§5.1) — being delivered on branch `qe-fix/issue-442` along with all confirmed #442 dep bumps.
2. Apply `safe_id_to_path` to all 3 recording sites (§3) — independent of the auth question.

### Pending Ruv-confirmation (separate issues)

3. Sensing-server auth design (§2) — opening separate issue; needs intent confirmation before implementing.
4. ESP32 OTA fail-open default (§4) — same: confirm whether dev-default is intentional.

### Sprint-1 (after #442 fix lands)

5. Fix axios direct dep + add npm overrides for the high-severity transitives (§5.3).
6. Wire `cargo audit` into CI (§5.5).
7. Migrate `TokenBlacklist` to Redis (§6).

### Sprint-1

6. ESP32 OTA: refuse empty PSK by default; add `--ota-psk` to `provision.py` (§4).
7. Wire `cargo audit` into CI (§5.5).
8. Migrate `TokenBlacklist` to Redis (§6).
9. Decide whether to rewrite git history for the leaked token (§1.3).

### Hygiene / ongoing

8. Pre-commit `gitleaks` hook.
9. `dependabot.yml` for github-actions ecosystem (delivered on the #442 fix branch).
10. Pin Docker base images to digests + non-root user.
11. Review and harden the auto-update submodule workflow.
12. Reply to issue #442 with the misattribution feedback (`dashboard/` does not exist; range/fix mismatch on `@xmldom/xmldom` advisories) so the DevGuard scanner can improve.
13. Optional history scrub of the test-seed string in §1.

---

## 9. How #442 compares to the actual risk picture

A useful reframing: of the 8 distinct vulnerabilities I would call **actually-exploitable** in this repo today, **only 1 is in #442** (and even that one — Checkmarx KICS — is *theoretically* exploitable, with no secrets in the affected job and limited blast radius).

| Source | Exploitable items found | Notes |
|--------|-------------------------|-------|
| Issue #442 (DevGuard scanner) | 1 (theoretical) | Plus 2 misattributions and 1 false-positive |
| Project-wide audit (this report) | 7 | Including the leaked token + unauth API + path traversal |

This is not a critique of issue #442 — third-party scanners are useful precisely because they catch one class of issue cheaply. But it's a strong argument for *also* running the kind of code-aware audit this report represents on a regular cadence (e.g., quarterly), not just relying on dependency-CVE scanners.
