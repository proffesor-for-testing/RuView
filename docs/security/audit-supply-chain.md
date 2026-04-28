# Supply Chain & CI/CD Security Audit — RuView (wifi-densepose)

Date: 2026-04-28 — Branch: qe-reports — HEAD: 110e34f5
Scope: GitHub Actions, npm/pip/cargo deps, submodules, Docker. Application code & auth excluded.

## Executive Summary

- **7 third-party Actions pinned to mutable refs** (`@master`/`@main`) across `security-scan.yml` (6) and `ci.yml` (1) — concentrated exactly in jobs that hold `SNYK_TOKEN`, `SEMGREP_APP_TOKEN`, `GITLEAKS_LICENSE`, and `security-events: write`. This is the highest-impact finding in the report.
- **JS/Mobile (`ui/mobile`): 25 advisories** (5 high, 16 moderate, 4 low) confirmed via `npm audit`. Includes the three flagged packages — `@xmldom/xmldom@0.8.11`, `node-forge@1.3.3`, `picomatch@2.3.1` — plus `axios@1.13.6` (direct, SSRF), `lodash@4.17.23` (high), `follow-redirects@1.15.11`, `brace-expansion`, `postcss`, `expo` (direct).
- **JS/Desktop UI: 3 advisories** (2 high, 1 moderate). `vite@6.4.1` (direct dev dep) is vulnerable to GHSA-p9ff-h696-f583 (arbitrary file read via dev-server WebSocket) and GHSA-4w7w-66w2-5vf9 (path traversal).
- **Python pins are minimal and not obviously vulnerable** (only numpy/scipy/pydantic locked); `requirements.txt` uses lower bounds (`>=`) for `python-jose`, `passlib`, `cryptography`-via-extras, `paramiko`, `aiohttp` — drift risk for prod images that re-resolve at build time. `pip-audit` is not installed in the workspace; recommend running in CI.
- **Submodule auto-update workflow tracks `main` of three external `ruvnet/*` repos every 6 hours** with `contents: write` + `pull-requests: write` and auto-opens PRs — this is a TOCTOU/upstream-takeover lever; if any of those three repos is compromised, a PR lands within 6 hours. Combined with mutable-ref Actions running on PRs, the blast radius compounds. Also: `docker-compose.yml` uses `image: ruvnet/wifi-densepose:latest` (mutable tag).

---

## 1. GitHub Actions — Mutable / Risky Refs

| Action | Ref | File:Line | Secret Exposed | Permissions | Severity |
|---|---|---|---|---|---|
| `snyk/actions/python` | `@master` | `.github/workflows/security-scan.yml:114` | `SNYK_TOKEN` | `security-events: write` (job), `actions: read`, `contents: read` | **CRITICAL** |
| `aquasecurity/trivy-action` | `@master` | `.github/workflows/security-scan.yml:166` | none direct | `security-events: write` | HIGH |
| `aquasecurity/trivy-action` | `@master` | `.github/workflows/ci.yml:258` | runs in same job that uses `GITHUB_TOKEN` for ghcr.io login (line 221) | (no `permissions:` block on `ci.yml` job — defaults permissive) | **CRITICAL** |
| `bridgecrewio/checkov-action` | `@master` | `.github/workflows/security-scan.yml:224` | none direct | `security-events: write` | HIGH |
| `tenable/terrascan-action` | `@main` | `.github/workflows/security-scan.yml:241` | none direct | `security-events: write` | HIGH |
| `checkmarx/kics-github-action` | `@master` | `.github/workflows/security-scan.yml:250` | none direct | `security-events: write` | HIGH |
| `trufflesecurity/trufflehog` | `@main` | `.github/workflows/security-scan.yml:280` | runs in `secret-scan` job alongside GitLeaks (`GITLEAKS_LICENSE` at line 291); `fetch-depth: 0` means full git history is in workdir | `security-events: write` | **CRITICAL** |
| `returntocorp/semgrep-action` | `@v1` | `.github/workflows/security-scan.yml:56` | `SEMGREP_APP_TOKEN` | `security-events: write` | HIGH (mutable major tag; vendor `returntocorp` was renamed to `semgrep` — also stale namespace) |

All other actions are pinned to a major-version tag (`@v3`/`@v4`/`@v5`/`@v6`/`@v2` — better than `@master` but still movable). **None are pinned to a SHA**, which is the GitHub-recommended SLSA-2 baseline. This includes first-party `actions/checkout@v4`, `actions/setup-python@v5`, `docker/build-push-action@v5`, `softprops/action-gh-release@v2`, `8398a7/action-slack@v3`, `peaceiris/actions-gh-pages@v4`, `gitleaks/gitleaks-action@v2`, `dtolnay/rust-toolchain@stable`, `azure/setup-kubectl@v3`, etc.

Why "mutable + secrets" matters: a maintainer-account or CI-token compromise of any third-party action repo lets the attacker exfiltrate the secret on the next workflow run. `snyk/actions`, `trufflesecurity/trufflehog`, and `aquasecurity/trivy-action` have all been targeted historically (or are namespaces with high attacker value). The `trivy-action@master` line in `ci.yml:258` is the worst because that job (`docker-build`) also runs `docker/login-action@v3` with `${{ secrets.GITHUB_TOKEN }}` for `ghcr.io` push — a supply-chain action there can publish a tampered image.

## 2. Workflow Secret Surface & `permissions:` Blocks

| Workflow | Secrets used | Top-level `permissions:` | Risk |
|---|---|---|---|
| `cd.yml` | `KUBE_CONFIG_DATA`, `KUBE_CONFIG_DATA_STAGING`, `KUBE_CONFIG_DATA_PRODUCTION`, `SLACK_WEBHOOK_URL` | **none** (defaults to read-all on `contents`, write on others depending on org policy) | **HIGH** — kubeconfigs for prod & staging in env block |
| `ci.yml` | `GITHUB_TOKEN` (used as ghcr password), `SLACK_WEBHOOK_URL` | **none** | HIGH — pushes images to `ghcr.io` from an unscoped job |
| `security-scan.yml` | `SEMGREP_APP_TOKEN`, `SNYK_TOKEN`, `GITHUB_TOKEN`, `GITLEAKS_LICENSE`, `SECURITY_SLACK_WEBHOOK_URL` | per-job: `security-events: write`, `actions: read`, `contents: read` (good) | High because of mutable refs above |
| `desktop-release.yml` | `TAURI_SIGNING_PRIVATE_KEY`, `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | per-job (`create-release` only): `contents: write`. Build jobs that read the signing key have **no `permissions:` block**. | **HIGH** — code-signing key flows through a default-permissive job |
| `update-submodules.yml` | `GITHUB_TOKEN` | top-level: `contents: write`, `pull-requests: write` | HIGH (see §6) |
| `firmware-ci.yml`, `firmware-qemu.yml`, `verify-pipeline.yml` | none | none | LOW (no secrets) but should still drop to `contents: read` |

Recommended baseline (`permissions: { contents: read }` at workflow top-level, escalated per-job only) is followed only in `security-scan.yml`.

## 3. JS Dependency Vulnerabilities — `ui/mobile/package-lock.json`

`npm audit --package-lock-only` summary: **25 total — 0 critical, 5 high, 16 moderate, 4 low**. The named-and-shamed packages from the threat report are all present, plus several others worth fixing:

| Package | Installed | Severity | Advisory | CVSS | Path | Fix |
|---|---|---|---|---|---|---|
| `@xmldom/xmldom` | 0.8.11 | high | GHSA-wh4c-j3r5-mjhp (XML inj via CDATA), GHSA-2v35-w6hq-6mfw (DoS), GHSA-f6ww-3ggp-fr8h, GHSA-x6wf-f3px-wcqx, GHSA-j759-j44w-7fr8 | 7.5 | `node_modules/@xmldom/xmldom` (transitive via expo) | bump to ≥0.8.13 — `npm audit fix` does it |
| `node-forge` | 1.3.3 | high | GHSA-2328-f5f3-gj25 (basicConstraints bypass), GHSA-q67f-28xg-22rw (Ed25519 sig forgery), GHSA-5m6q-g25r-mvwx (DoS modInverse) | 7.4-7.5 | `node_modules/node-forge` (transitive) | bump to current 1.3.x patched line; `audit fix` handles |
| `picomatch` | 2.3.1 (also 4.0.3) | high | GHSA-c2c7-rcm5-vvqj (ReDoS via extglob), GHSA-3v7f-55p6-f55p | 7.5 | multiple paths: `node_modules/anymatch/node_modules/picomatch`, `jest-util/...`, `micromatch/...` | bump to ≥4.0.4 (and ensure 2.x callers move to ≥3.x) |
| `axios` | 1.13.6 | moderate | GHSA-3p68-rc4w-qgx5 (NO_PROXY SSRF), GHSA-fvcv-3m26-pcqx (cloud-metadata exfil via header injection) | 4.8 | `node_modules/axios` — **direct dep** (`package.json:19`) | bump to ≥1.15.0 |
| `lodash` | 4.17.23 | high | GHSA-r5fr-rjxr-66jc (`_.template` code injection), GHSA-f23m-r3pf-42rh (proto pollution `_.unset`/`_.omit`) | 8.1 / 6.5 | `node_modules/lodash` (transitive) | bump to current 4.17.x patched line (≥4.17.24) |
| `follow-redirects` | 1.15.11 | moderate | GHSA-r4q5-vmmm-2653 (cross-domain auth-header leak) | (npm reports moderate, score 0 in feed) | transitive | bump to ≥1.15.12 |
| `brace-expansion` | 1.1.12 / 2.0.2 / 5.0.4 | moderate | GHSA-f886-m6hf-6m8v (zero-step DoS) | 6.5 | many `node_modules/.../brace-expansion` | `audit fix` |
| `postcss` | 8.4.49 | moderate | GHSA-qx2v-qp2m-jg93 (XSS via unescaped `</style>`) | 6.1 | transitive | bump to ≥8.5.10 |
| `expo` | direct | moderate | dependency-tree on `@expo/cli`, `@expo/config-plugins` | — | direct (`package.json:20`) | major bump path: `expo@49.0.23` per audit, but lock declares `~55.0.4` already — likely false signal from old expo subdep tree; **flag as needs-verification, not actionable as audit suggests** |

**Vite (desktop UI, `rust-port/wifi-densepose-rs/crates/wifi-densepose-desktop/ui/package-lock.json`):**

| Package | Installed | Severity | Advisory | CVSS | Path | Fix |
|---|---|---|---|---|---|---|
| `vite` | 6.4.1 | high | GHSA-p9ff-h696-f583 (dev-server WebSocket arbitrary file read), GHSA-4w7w-66w2-5vf9 (path traversal `.map`) | 7.x | `node_modules/vite` — **direct devDep** (`package.json:23`, `^6.0.0`) | bump to ≥6.4.2 (npm reports 6.4.1 as last vulnerable) |
| `picomatch` | 4.0.3 | high | GHSA-c2c7-rcm5-vvqj | 7.5 | transitive | bump to ≥4.0.4 |
| `postcss` | 8.5.8 | moderate | GHSA-qx2v-qp2m-jg93 | 6.1 | transitive | bump to ≥8.5.10 |

`expo`-direct, `vite`-direct, and `axios`-direct are the three lock-file changes that need a human review (lockfile churn beyond `audit fix`).

## 4. Python Dependency Findings

`pip-audit` is **not installed** in the workspace (verified). Tools listed in `security-scan.yml:101` (`safety`, `pip-audit`) only run in CI, so I cannot ground new advisories from local tool output. From manual review:

- `requirements.txt` uses lower-bound pins (`>=`) only. This is fine for dev but means production images that don't re-pin will resolve floating versions. The Dockerfile.python pins through `v1/requirements-lock.txt`, but the **lock file only pins `numpy`, `scipy`, `pydantic`, `pydantic-settings`** — it does NOT pin `python-jose`, `passlib`, `cryptography`, `requests`, `urllib3`, `paramiko`, `aiohttp`, `fastapi`, `uvicorn`, etc. So the production Docker image at build time installs whatever pip resolves that day for security-critical libs.
- Auth-relevant deps from `requirements.txt`: `python-jose[cryptography]>=3.3.0` and `passlib[bcrypt]>=1.7.4` — both have known issues at oldest-allowed versions; `python-jose` 3.3.0 has CVE-2024-33663 (algorithm confusion) and CVE-2024-33664 (DoS via JWE). The `>=3.3.0` constraint allows a vulnerable resolution.
- Recommend: regenerate `v1/requirements-lock.txt` to include all transitive deps with hashes (`pip-compile --generate-hashes` or equivalent), and run `pip-audit -r v1/requirements-lock.txt` in CI without `continue-on-error: true`.

## 5. Rust Dependency Findings

`cargo-audit` not installed; results below are from inspecting `rust-port/wifi-densepose-rs/Cargo.lock` against publicly known advisories:

| Crate | Locked version | Status | Note |
|---|---|---|---|
| `openssl` | 0.10.75 | **OK** | ≥0.10.55, no current open advisory |
| `openssl-sys` | 0.9.111 | OK | matches above |
| `time` | 0.3.47 | OK | ≥0.2.23 |
| `smallvec` | 1.15.1 | OK | ≥1.8.0 |
| `hyper` | 1.8.1 | OK | ≥0.14.10 |
| `tokio` | 1.49.0 | OK | ≥1.18.4 |
| `axum` | 0.7.9 | OK | active line |
| `chrono` | 0.4.44 | OK | post 0.4.20 segfault patch |
| `rustls` | 0.22.4 / 0.23.37 | OK | both above CVE-2024-32650 fix (≥0.22.4 / ≥0.23.5) |
| `reqwest` | 0.12.28 / 0.13.2 | OK | active lines |
| `tungstenite` | 0.24.0 | OK | post-RUSTSEC-2023-0065 |

No clearly-vulnerable pins detected via lockfile pattern matching. **However**, `cargo audit` should still be wired into `firmware-ci.yml` / `ci.yml` — currently neither workflow runs it, which is a CI gap. (Run `cargo install cargo-audit && cd rust-port/wifi-densepose-rs && cargo audit` in a new job.)

## 6. Submodules & Vendor / Docker Findings

**Submodules (`.gitmodules`):** all three track `branch = main` (mutable):

| Path | URL | Pinned SHA | Tracking |
|---|---|---|---|
| `vendor/midstream` | `https://github.com/ruvnet/midstream` | `30fe5eb7a1f1494aa1ad00d54160088a565ec766` | `main` |
| `vendor/ruvector` | `https://github.com/ruvnet/ruvector` | `050c3fe6f878981250cb62d4003f47b42d290973` | `main` |
| `vendor/sublinear-time-solver` | `https://github.com/ruvnet/sublinear-time-solver` | `1210646955f33abe5c91f894cc7b04d024f62408` | `main` |

`update-submodules.yml` runs every 6h, fetches the latest `main` of each, auto-opens a PR with `contents: write` + `pull-requests: write`. If any of the three upstream repos is compromised, malicious code lands in a PR within 6h. The vendored `vendor/ruvector/` is also `COPY`d straight into `Dockerfile.rust:14`, meaning a compromised upstream propagates into the production Rust image build with no review beyond PR merge.

**Docker:**

| Issue | Where | Severity |
|---|---|---|
| `image: ruvnet/wifi-densepose:latest` (mutable tag) | `docker/docker-compose.yml:8` | MEDIUM |
| `image: ruvnet/wifi-densepose:python` (mutable tag, no digest) | `docker/docker-compose.yml:33` | MEDIUM |
| Base image `python:3.11-slim-bookworm` not pinned to digest | `docker/Dockerfile.python:4` | LOW |
| Base image `rust:1.85-bookworm` not pinned to digest | `docker/Dockerfile.rust:6` | LOW |
| Final stage `debian:bookworm-slim` not pinned to digest | `docker/Dockerfile.rust:21` | LOW |
| **No `USER` directive — both images run as root** | `Dockerfile.python` (no USER), `Dockerfile.rust` (no USER) | MEDIUM |
| `pip install … websockets uvicorn fastapi` after lock-file install — re-resolves outside the lockfile | `Dockerfile.python:15` | MEDIUM |

## 7. Prioritized Remediation Plan

### P0 — within this PR cycle

1. **Pin all third-party Actions to commit SHAs.** Highest ROI fix in this audit. Replace each mutable line, e.g.:
   - `.github/workflows/security-scan.yml:114` → `uses: snyk/actions/python@<commit-sha>  # was @master`
   - same treatment for trivy, checkov, terrascan, kics, trufflehog (and tighten semgrep-action to a SHA).
   - `.github/workflows/ci.yml:258` → `uses: aquasecurity/trivy-action@<sha>`
   - Use `gh api repos/<owner>/<repo>/git/refs/tags/<latest-tag>` to fetch the SHA, or `gh api repos/<owner>/<repo>/commits/master --jq .sha`. Add a Renovate/Dependabot config to bump SHAs.
2. **Add `permissions: { contents: read }` at the top of `cd.yml`, `ci.yml`, and `desktop-release.yml`**, then escalate per-job only where required (ghcr push needs `packages: write`, gh-release needs `contents: write`). Currently all three rely on org defaults which are typically permissive.
3. **`cd ui/mobile && npm audit fix`** — resolves 22+ of the 25 advisories non-breaking. Then bump direct `axios` from `^1.13.6` to `^1.15.0` in `package.json`.
4. **Bump desktop-ui Vite:** `cd rust-port/wifi-densepose-rs/crates/wifi-densepose-desktop/ui && npm install vite@^6.4.2` then `npm audit fix`.
5. **Replace mutable Docker tags:** `docker/docker-compose.yml:8` and `:33` — pin to `@sha256:<digest>` of the latest published image, OR drop the `image:` line entirely and rely on `build:`.

### P1 — within the next sprint

6. **Throttle `update-submodules.yml`:** drop frequency from `0 */6 * * *` (4×/day) to weekly, and restrict the auto-PR to a tag-watch instead of `main`. Alternative: replace `git submodule update --remote --merge` with a hash-pin workflow that requires a maintainer to confirm the new SHA.
7. **Add `cargo audit` job to `ci.yml`** under the existing `test` matrix (`cargo install cargo-audit --locked && cargo audit`).
8. **Generate a hashed Python lockfile** for the production image: `pip-compile --generate-hashes -o v1/requirements-lock.txt v1/requirements-in.txt` covering ALL transitive deps (currently only 4 are pinned). Then `pip install --require-hashes -r v1/requirements-lock.txt` in `Dockerfile.python`.
9. **Add `USER nonroot` to both Dockerfiles** before the `CMD`/`ENTRYPOINT`. Create a `nonroot` user with `RUN useradd -r -u 10001 nonroot && chown -R nonroot /app`.
10. **Drop `continue-on-error: true`** from the safety/pip-audit/snyk steps in `security-scan.yml` (lines ~106, 111, 119) — silent security failures are worse than no scan.

### P2 — backlog

11. Add `harden-runner` (Step Security) at the top of every job to monitor egress and detect post-compromise exfil from compromised actions.
12. Sign release artifacts (`desktop-release.yml`) with cosign / Sigstore in addition to the Tauri signing key, store provenance with SLSA Level 3.
13. Add Dependabot or Renovate config in `.github/dependabot.yml` for `npm` (both lock files), `cargo`, `pip`, `github-actions`, and `docker`.

---

### Verification commands run during this audit

- `grep -rnE 'uses:.*@(main|master|latest)$' .github/workflows/` — 7 hits (raw output above).
- `cd ui/mobile && npm audit --json --package-lock-only` — 25 advisories, 5 high.
- `cd rust-port/wifi-densepose-rs/crates/wifi-densepose-desktop/ui && npm audit --package-lock-only` — 3 advisories, 2 high.
- `git submodule status` — 3 SHAs captured.
- `pip-audit` — **NOT INSTALLED**, marked as "best effort, no result captured" per task spec.
- `cargo-audit` — **NOT INSTALLED**, lockfile pattern-match performed instead; flagged as not authoritative.

### Notes on potential false positives

- `expo` direct dep flagged moderate by `npm audit` — the audit suggests downgrading to `expo@49.0.23` while the lock file declares `~55.0.4`. This is the Expo SDK transitively pulling old `@expo/config-plugins` paths from internal nested `node_modules`. Likely a stale advisory tree, not a real exploit vector. **Verify before bumping** — could be a no-op or a breaking-version cascade.
- All `@xmldom/xmldom`, `node-forge`, `lodash`, `picomatch` finds are deep-transitive through the `expo` / `react-native` toolchain. Runtime exposure depends on whether those code paths execute at app runtime vs only at build time. CVSS scores quoted are the npm advisory's published scores; a few report `score: 0` (unscored by NVD) and were left as the npm-reported severity.

Word count: ~1450.
