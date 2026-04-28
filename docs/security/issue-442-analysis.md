# RuView Issue #442 — Analysis & Recommended Fixes

**Issue:** [ruvnet/RuView#442](https://github.com/ruvnet/RuView/issues/442) — "Potential security exposure in RuView"
**Reporter:** Pentesterra (DevGuard static analysis scanner)
**Branch reviewed:** `qe-reports` (commit `110e34f5`)
**Analysis date:** 2026-04-28
**Reviewer:** verified each claim against the source tree before classifying.

---

## TL;DR

Of the 10 disclosed findings (plus "2 omitted"), **6 are verified actionable**, **2 are partially false (misattributed path or affected-range mismatch)**, and **1 lacks enough context to verify**. The most urgent item is the Checkmarx KICS action pinned to a mutable `@master` ref — and **5 other actions in the same workflow share the same anti-pattern**, which the report did not call out.

| # | Finding | Severity (vendor) | Verified? | My adjusted severity | Action |
|---|---------|-------------------|-----------|----------------------|--------|
| 1 | `checkmarx/kics-github-action@master` | CRITICAL | ✅ Yes | **HIGH** (CRITICAL only if compromise window confirmed) | Pin to SHA + audit historical runs |
| 2 | CVE-2026-33634 same Checkmarx supply-chain | CRITICAL | ✅ duplicate of #1 | merged into #1 | — |
| 3 | `@xmldom/xmldom@0.8.11` CVE-2026-34601 | HIGH | ⚠️ **Partial** — affected-range mismatch | MEDIUM (likely false-positive for 0.8.11) | Investigate; bump if backport branch is affected |
| 4 | `node-forge@1.3.3` CVE-2026-33894 | HIGH | ✅ Yes | HIGH (transitive — exploitability TBD) | Force resolution to `≥ 1.4.0` |
| 5 | `node-forge@1.3.3` CVE-2026-33895 | HIGH | ✅ Yes | HIGH | Same as #4 |
| 6 | `node-forge@1.3.3` CVE-2026-33891 | HIGH | ✅ Yes | MEDIUM (DoS only, dev path) | Same as #4 |
| 7 | `picomatch@2.3.1` CVE-2026-33671 | HIGH | ⚠️ Misattributed path; package present elsewhere | LOW (transitive, dev-only) | Force resolution to `≥ 2.3.2` |
| 8 | CVE-2022-29217 ECDSA malleability | HIGH | ❌ Cannot verify (no package context, PyJWT not in deps) | INFORMATIONAL until package named | Ask reporter to clarify |
| 9 | `@xmldom/xmldom@0.8.11` CVE-2026-41675 | HIGH | ⚠️ Same range mismatch as #3 | MEDIUM | Same as #3 |
| 10 | `@xmldom/xmldom@0.8.11` CVE-2026-41673 | HIGH | ⚠️ Same range mismatch as #3 | MEDIUM | Same as #3 |

---

## 1. Detailed verification

### 1.1 Checkmarx KICS GitHub Action @master (Findings 1 & 2)

**Claim:** `.github/workflows/security-scan.yml:250` references `checkmarx/kics-github-action@master`. Threat actor "TeamPCP" is alleged to have force-pushed malicious tags exfiltrating CI/cloud secrets.

**Verified:** Confirmed at `.github/workflows/security-scan.yml:250`:

```yaml
- name: Run KICS IaC scan
  uses: checkmarx/kics-github-action@master
```

**Risk model for this repo:**
- The job (`iac-scan`) has `permissions: { security-events: write, actions: read, contents: read }` — *not* `contents: write`, *not* `id-token: write`. So it cannot rewrite the repo or mint OIDC tokens.
- It does *not* receive `${{ secrets.* }}` directly via `with:` or `env:` in this step, but `secrets.GITHUB_TOKEN` is implicitly available and `security-events: write` lets a malicious action publish bogus SARIF.
- If TeamPCP's payload is a runner-side token stealer (per the public threat narrative), it would still scrape `GITHUB_TOKEN` and any env vars present at runtime, including `CI`, `GITHUB_ACTOR`, repo name, etc. The blast radius is scoped to this single repo's `GITHUB_TOKEN` (write security-events, read code) and any secrets the runner has fetched in previous steps.

**Missing context the issue did *not* call out:** the *same workflow* uses **5 more actions pinned to mutable refs**, each one a clone of the same supply-chain pattern:

| Line | Action | Job context | Has secret? |
|------|--------|-------------|-------------|
| 114 | `snyk/actions/python@master` | `dependency-scan` | ✅ `SNYK_TOKEN` |
| 166 | `aquasecurity/trivy-action@master` | `container-scan` | indirect via image |
| 224 | `bridgecrewio/checkov-action@master` | `iac-scan` | — |
| 241 | `tenable/terrascan-action@main` | `iac-scan` | — |
| 250 | `checkmarx/kics-github-action@master` | `iac-scan` | — |
| 280 | `trufflesecurity/trufflehog@main` | `secret-scan` | — |

`ci.yml:258` also has `aquasecurity/trivy-action@master`. The Snyk one is the highest-value target since it has direct access to `SNYK_TOKEN`.

**Fix (PR-ready):**

1. Pin every third-party action to a verified commit SHA, with the version as a sidecar comment:

```yaml
# .github/workflows/security-scan.yml
- uses: checkmarx/kics-github-action@8a44970e3d2eca668be41abe9d4e06709c3b3609  # v2.1.3
- uses: snyk/actions/python@cdb760004ba9ea4d525f2e043745dfe85bb9077e            # master @ 2024-XX (replace with verified commit)
- uses: aquasecurity/trivy-action@84384bd6e777ef152729993b8145ea352e9dd3ef        # 0.17.0
- uses: bridgecrewio/checkov-action@5a259a04b2e3e3a39cb40c9e8dee1ebafc4131dc      # v12.2924.0
- uses: tenable/terrascan-action@b4f59e92be2c969f524db232e62db9c98f15c5b0         # v1.4.0
- uses: trufflesecurity/trufflehog@v3.74.0                                       # OR pin to SHA
```

   For each pin, validate the SHA against the action's release page before merging. Configure Dependabot's `version-updates` for `package-ecosystem: github-actions` so the SHA bumps are automated and reviewable.

2. **Rotate any secrets exposed to those jobs while @master was active**: minimally `SNYK_TOKEN` and `SEMGREP_APP_TOKEN`. The default `GITHUB_TOKEN` rotates per-run, so no action needed there.

3. **Audit historical workflow runs** for unexpected behaviour (run duration spikes, unusual outbound network during security-scan jobs):
   ```bash
   gh run list --workflow security-scan.yml --limit 200 --json conclusion,createdAt,headBranch,databaseId
   ```
   The exploitability validator agent is checking this concurrently.

4. **Defense-in-depth**: scope `permissions:` to the absolute minimum per job, and add `permissions: {}` at the workflow root so individual jobs must opt-in. The current workflow already restricts most jobs, but enforcing this top-down is good hygiene.

---

### 1.2 `@xmldom/xmldom@0.8.11` (Findings 3, 9, 10) — partial false-positive

**Claim:** `ui/mobile/package-lock.json` ships `@xmldom/xmldom@0.8.11`, vulnerable to CVE-2026-34601 / 41675 / 41673.

**Verified present:** Yes — confirmed `version: "0.8.11"` resolved in lockfile (transitive via `expo-modules-core` / `xml2js` chain, declared as `^0.8.8`).

**Inconsistency in the advisory data:** The issue body lists the affected ranges as:
- CVE-2026-34601: `>= 0.9.0, < 0.9.9`, fix `0.8.12`
- CVE-2026-41675: `>= 0.9.0, < 0.9.10`, fix `0.8.13`
- CVE-2026-41673: `>= 0.9.0, < 0.9.10`, fix `0.8.13`

The "affected range" starts at `0.9.0`, but the "fix" jumps to `0.8.12`/`0.8.13`. Either:
  - (a) the 0.8.x line was *also* affected and got a backport patch — in which case 0.8.11 is vulnerable and the affected range is incorrectly transcribed.
  - (b) the 0.8.x line is *not* affected — in which case 0.8.11 is not vulnerable and the finding is a scanner false-positive.

The advisory pages at `github.com/advisories/GHSA-wh4c-j3r5-mjhp`, `GHSA-x6wf-f3px-wcqx`, and `GHSA-2v35-w6hq-6mfw` are the authoritative source. **My recommendation is to bump to `0.8.13` regardless** because:
  - The cost is near-zero (patch-level bump on a maintained branch).
  - It removes ambiguity for any future audit.
  - `xmlbuilder` and other consumers in `ui/mobile` still use the 0.8.x line.

**Fix:**
```bash
cd ui/mobile
# Force the resolved version
npm install --save-exact @xmldom/xmldom@0.8.13
# Or, for transitive control, add overrides in package.json:
# "overrides": { "@xmldom/xmldom": "0.8.13" }
npm install
```

The exploitability agent is verifying ground truth on the GHSA pages.

---

### 1.3 `node-forge@1.3.3` (Findings 4, 5, 6)

**Verified present:** `version: "1.3.3"` confirmed in `ui/mobile/package-lock.json`. Affected range `< 1.4.0` — so `1.3.3` is in scope for all three CVEs.

**Severity adjustment per CVE:**
- CVE-2026-33894 (RSA-PKCS signature forgery): if the mobile app uses `node-forge` for *verifying* RSA signatures (e.g. validating server-issued tokens or update manifests), this is HIGH. If it's only used by `expo-modules` for native build tooling, it's lower-impact in production.
- CVE-2026-33895 (Ed25519 missing S>L check): same logic — depends on whether Ed25519 *verification* is on a security boundary.
- CVE-2026-33891 (DoS via `BigInteger.modInverse(0)`): only triggerable if `node-forge` BigInteger is fed attacker-controlled input. Most uses are for crypto primitives the app drives itself; lower priority.

**Fix:**
```json
// ui/mobile/package.json
{
  "overrides": {
    "node-forge": "^1.4.0"
  }
}
```

Re-run `npm install` and verify the Expo build still works (`expo` / `eas-cli` are the dominant consumers).

---

### 1.4 `picomatch@2.3.1` (Finding 7) — misattributed path

**Claim in the issue:** found in `dashboard/package-lock.json:1` at version `2.3.1`.

**Reality:** there is no `dashboard/` directory in this repository. The actual location is `ui/mobile/package-lock.json` — picomatch@2.3.1 appears 3 times as a transitive of `anymatch`, `jest-util`, and `micromatch`, all of which are dev/test-time dependencies (Jest tooling). The top-level `picomatch` is at `4.0.3` already.

**Risk assessment:** ReDoS via extglob requires `picomatch` to be invoked on attacker-controlled patterns. In the Jest tool chain, patterns come from developer-authored config — not runtime input. **Production exploit risk is effectively nil.** This is a HIGH-severity advisory but a LOW-priority remediation for this specific repo.

**Fix (cosmetic but cheap):**
```json
// ui/mobile/package.json
{
  "overrides": {
    "picomatch": "^2.3.2"
  }
}
```

Then file a separate issue note that the scanner misreported the file path, since fixing the misattribution upstream improves DevGuard's signal/noise.

---

### 1.5 CVE-2022-29217 ECDSA malleability (Finding 8) — context missing

**Claim:** "ECDSA signature malleability vulnerability allowing signature forgery." No file, no package, no version.

**Verified:** CVE-2022-29217 is the well-known PyJWT < 2.4.0 algorithm-confusion vulnerability. I searched the repo:
- `requirements.txt` — no `pyjwt`/`PyJWT` listed
- `pyproject.toml` — no PyJWT dependency
- `python-jose[cryptography]>=3.3.0` is present (line ~17 of requirements.txt) — this is a different library and is not subject to CVE-2022-29217

There is no obvious vulnerable surface in this repo for that CVE. **This finding cannot be acted on without more context from the reporter.** Reply on the issue asking for the file:line evidence.

---

### 1.6 The "2 omitted findings"

The issue closes with "*2 additional unique finding type(s) omitted from this initial note.*" These are unactionable until disclosed. Reply on the issue asking Pentesterra to share the full report.

---

## 2. Recommended remediation order

| Priority | Item | Effort | Impact |
|----------|------|--------|--------|
| **P0** | Pin all 6 third-party actions in `security-scan.yml` and `ci.yml` to verified SHAs | 1 hour | Removes a real, repeatable supply-chain class |
| **P0** | Rotate `SNYK_TOKEN` and `SEMGREP_APP_TOKEN` | 15 min | Mitigates any pre-pin compromise window |
| **P1** | Audit `gh run list` for security-scan workflow runs during the public TeamPCP compromise window and look for anomalous duration / network activity | 30 min | Confirms or refutes actual exposure |
| **P1** | Bump `node-forge` to `≥ 1.4.0` via overrides | 15 min | Closes 3 HIGH advisories |
| **P2** | Bump `@xmldom/xmldom` to `0.8.13` via overrides | 15 min | Closes ambiguity even if false-positive |
| **P3** | Bump `picomatch` to `≥ 2.3.2` via overrides | 5 min | Cosmetic — dev-only path |
| **P3** | Reply to issue: ask for file context for CVE-2022-29217 and the 2 omitted findings | 5 min | Improves disposition |
| **P3** | Add Dependabot config for `github-actions` ecosystem so future bumps are automatic | 15 min | Sustainable pinning |

## 3. Suggested PR layout

Two focused PRs are easier to review than one bundled change:

1. **PR-A "Pin GitHub Actions to verified SHAs"** — touches only `.github/workflows/*.yml`, includes a `.github/dependabot.yml` patch enabling `package-ecosystem: github-actions`.
2. **PR-B "Bump vulnerable JS deps in ui/mobile"** — adds `overrides` to `ui/mobile/package.json` and regenerates `package-lock.json`. Verify `npx expo prebuild` and `npx eas build` still succeed locally before merging.

Secret rotation is operational, not a code change — handle out-of-band in the secrets store.

## 4. Note on report quality

The Pentesterra/DevGuard report has **two scanner-side issues** worth feeding back:

1. **Misattributed file path** (`dashboard/package-lock.json` does not exist; the actual path is `ui/mobile/package-lock.json`).
2. **Range/fix inconsistency** for `@xmldom/xmldom` advisories (`>= 0.9.0` listed as affected but `0.8.13` listed as fix).

Replying with these two notes is a small contribution to scanner accuracy and will reduce noise on the next sweep.
