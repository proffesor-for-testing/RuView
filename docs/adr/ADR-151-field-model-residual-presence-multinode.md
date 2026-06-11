# ADR-151: Field-Model Residual Occupancy for Reliable Presence (Multi-Node, Empty-Baseline)

## Status

Proposed

## Date

2026-06-11

## Deciders

ruv, Dragan (proffesor-for-testing)

## Related

ADR-018 (CSI frame format), ADR-024 (contrastive CSI embeddings), ADR-029 (multistatic sensing), ADR-030 (persistent field model — `ruvsense/field_model.rs`), ADR-039 (ESP32 edge intelligence / vitals packet), ADR-059 (live ESP32 CSI pipeline). Field firmware bug `RuView#996` (presence threshold). Surfaced from a Cognitum Seed support case (Health Monitor presence never locks).

---

## 1. Context

### 1.1 The symptom

In the Cognitum Seed deployment, contactless vitals (`source: auto:esp32-vitals`) read correctly (HR ~45–90, breathing ~10–30) but **presence almost never locks**, even with deliberate movement — so the safety rule (show vitals only when a real person is confirmed present) keeps vitals hidden. The dashboard correctly shows "Motion — No Lock".

### 1.2 Root cause — the seed/edge path uses the naive edge presence flag

The ESP32 vitals packet (`0xC5110002` / fused `0xC5110004`) carries a `presence` bit (flags bit0) computed in `edge_processing.c`:

```
presence_score = motion_energy = variance(phase_history[last 20 frames])
presence       = presence_score > threshold        // threshold: NVS pres_thresh, else mean+3σ auto-cal over ~60s
```

This is a **single-node, raw-phase-variance** feature. It does **not** use the ADR-030 field model (SVD environmental modes + residual + Marčenko–Pastur occupancy), which lives server-side in `ruvsense/field_model.rs` and is **not in the Seed/cog path**. The seed cogs (Health Monitor, etc.) gate on this naive flag.

### 1.3 Device investigation (real ESP32-S3 hardware, this is not simulated)

Two ESP32-S3 nodes (`80:b5:4e:c1:c4:f0`, `80:b5:4e:c1:be:b8`), RuView v0.7.1 firmware, single channel (2417 MHz, 64 subcarriers), streaming raw CSI (`0xC5110001`) to a collector. Data + scripts: `docs/adr/data/ADR-151-presence-field-model/`.

**Negative results — single node (what does NOT work):**

| Feature | Empty | Occupied (still) | Occupied (moving) | Discriminates? |
|---|---|---|---|---|
| phase/amplitude variance | 1.74 | 1.37 | 1.06 | No (backwards) |
| RSSI std | 1.22 | 0.85 | 0.50 | No (backwards) |
| breathing-band SNR (top-8) | 19.7 | 17.9 | 12.4 | No |
| raw covariance eigenvalues > MP floor | 16 | 15 | 18 | No |

Single-node CSI variation is dominated by **ambient drift** (other WiFi/building activity), not the subject. The naive edge feature cannot work; a fixed low `pres_thresh` only inverts the failure to **always-present** (empty-room `presence_score` overlaps occupied — verified false-positive, which would break the safety rule).

**The field-model residual (project out learned empty modes):** single node detects **motion** (2.7–4× empty) but **not a still person** (residual ≤ empty). A motionless body barely perturbs one link.

**Positive result — multi-node + field-model residual (what DOES work):**

Two nodes, 120 s empty-room baseline (per-node mean + top-K SVD environmental modes), residual energy of `observation − projection(empty modes)`, **max across nodes**:

| Capture | node1 | node2 | MAX | vs empty |
|---|---|---|---|---|
| empty (held-out) | 8.3 | 8.5 | 8.5 | 1× |
| **occupied — STILL** | 39 | 88 | **88** | **10×** |
| occupied — moving | 495 | 564 | 564 | 66× |

(K=8; held at K=12/16.) Moving person ~60×. **⚠️ See §1.4 — the "still ~10×" reading here did NOT hold up under controlled testing.**

### 1.4 Correction — controlled on-seed test (the residual detects MOTION, not static presence)

The numbers above were captured on a Mac collector with ~30–40 s "occupied still" windows. A **controlled test on a real seed** (cognitum-8b40, Pi armv7l; explicit empty-baseline calibration with the subject fully out of the room; then subject seated close + still, timing strictly controlled) corrected the interpretation:

```
arrival / settling (sitting down):  node1 2.8 → 3.8 → 3.9×   present=TRUE
held truly still ~15 s:             node1 0.7× (BELOW empty floor)  present=FALSE 14/14
```

**The implemented residual energy `‖(x−mean) − VkVkᵀ(x−mean)‖²` is a variation/motion measure.** A motionless body settles into a *stable, low-variation* CSI state whose residual decays back to — even below — the empty baseline. The earlier "still ~8–10×" almost certainly captured **settling + micro-motion**, not sustained stillness.

**Honest verdict:**
- ✅ **Motion / arrival / movement is detected robustly** on real hardware (on-seed 2.8–3.9× close, ~60× moving), with a fresh empty baseline.
- ❌ **A truly still person fades** (residual is variation-driven).
- **Fresh calibration is essential** — a stale baseline (RF drift between calibration and use) understates the signal; the on-seed test only worked after a fresh empty-room calibration (validates the ADR-030 persistent-field-model + drift handling, and the explicit-calibration UX).
- → **Sustained still-person presence requires the breathing-band approach** (detect the *periodic* breathing modulation, which persists when motionless), not raw residual energy. This is now a proven requirement, not a hypothesis.

Raw data: `docs/adr/data/ADR-151-presence-field-model/onseed_controlled_test.log`.

---

## 2. Decision

**Compute presence/occupancy from the ADR-030 field-model residual over multiple nodes, in the Seed/server path, and feed that presence to the cogs' vitals gating — replacing the ESP32 edge phase-variance flag for the presence decision.**

### 2.1 Method (reproducible; see `field_residual_mn.py`)

1. **Empty-room calibration** (explicit, ≥~2 min unoccupied): per node, accumulate CSI amplitude → baseline mean + covariance; SVD → top-K environmental eigenmodes; record the empty residual noise floor (the ADR-030 / #942 anchor).
2. **Runtime**: per node, `residual = (obs − mean) − V_k V_kᵀ (obs − mean)`; `residual_energy = ‖residual‖²` averaged over a short window.
3. **Occupancy/presence**: `present = max_over_nodes(residual_energy) > T`, with `T` anchored to the empty baseline (e.g. ~5–10× the empty residual). Reuse `estimate_occupancy`'s Marčenko–Pastur anchoring for the threshold rather than a hand-tuned constant.
4. **Latch** presence for a short hold time after detection (bridges a still-after-moving subject). NOTE: latching only bridges seconds — a person who stays motionless for longer un-latches, because the residual is motion-driven (§1.4). Robust static presence needs the breathing-band detector below.
5. **Breathing-band detector (required for static presence, §1.4):** on the residual time-series, detect the *periodic* ~0.1–0.5 Hz breathing modulation (autocorrelation / spectral-peak prominence), which persists for a motionless person. This — not raw residual energy — is what sustains presence for a still subject.

### 2.2 Where it runs

Server/seed side (it needs SVD + mode projection — not the MCU). Prefer reusing `ruvsense/field_model.rs` (`FieldNormalMode`, `estimate_occupancy`) over re-implementing; expose a multi-node presence signal the Cognitum cogs (Health Monitor) can gate on. The ESP32 edge presence flag is retained only as a coarse fallback, not the source of truth.

### 2.3 Calibration UX

An explicit **"learn empty room"** step at setup (the user leaves for ~2 min). Baseline persists with longitudinal drift handling and expiry per ADR-030. This was chosen over silent auto-learning to avoid learning an occupied room as "empty".

---

## 3. Consequences

**Positive**
- Reliable presence for a **moving / recently-arrived** person on real hardware (on-seed 2.8–3.9× close, ~60× moving). **Sustained still-person presence is NOT yet achieved** by the residual alone — it needs the breathing-band extension (§1.4).
- Reuses the existing field-model machinery and the contrastive/topological paradigm (ADR-024/029/030) instead of a brittle scalar threshold.
- Keeps the safety rule intact (no fabricated presence): empty stays clearly below threshold.

**Negative / costs**
- Requires **≥2 nodes** and an **empty-room calibration** step (deployment friction).
- Per-node SVD + mode projection is more compute than the edge flag (server-side; bounded — 64×64 covariance, periodic).
- Baseline must track environmental drift (furniture moves, APs change) — handled by ADR-030 longitudinal model + recalibration trigger.

**Neutral / follow-ups**
- True **multistatic** node-to-node links (ADR-029) and **breathing-band on the residual** should push still-person sensitivity and single-node viability further.
- Firmware fix `RuView#996` (auto-cal overshoot) and the **spurious fused/mmWave packet** (sends `0xC5110004` with zeroed mmWave fields when no radar is attached) remain valid separate fixes.
- Cog-side: decode `0xC5110004` as well as `0xC5110002` (first 32 bytes identical) so fused-mode nodes don't starve the cogs.

## 4. Alternatives considered

- **Tune the edge `pres_thresh`** — rejected; device-verified that empty ≈ occupied `presence_score`, so any fixed threshold either never locks or is always-on (false-positive presence, breaks the safety rule).
- **Single-node field-model residual** — detects motion but not a still person (device-verified); insufficient alone.
- **mmWave fusion** — no radar attached in this deployment; the firmware already emits garbage mmWave fields. A real mmWave sensor would help but is out of scope for the commodity-WiFi path.

## 5. Acceptance criteria

- Empty-room: presence False for ≥99% of a 10-min unoccupied run after calibration.
- Still person (sitting, breathing, ≤1 m from any node): presence True within 5 s, sustained.
- Walk-in/walk-out: presence transitions within 2 s, no false-positive in the empty windows.
- Multi-node (2–4 nodes), single channel, commodity ESP32-S3.

## 6. Evidence

`docs/adr/data/ADR-151-presence-field-model/`:
- `capture_mn.py` — multi-node CSI capture (separates by node_id).
- `field_residual_mn.py` — the field-model residual occupancy method.
- `mp_occupancy.py` — Marčenko–Pastur eigenvalue occupancy (single-node negative result).
- `results_multinode.txt` — the table above (K=8/12/16).
- `mn_{baseline,occstill,occmoving}.json.gz` — raw device captures (2 nodes, 120 s baseline + occupied still/moving).

🤖 Generated with Ruflo & AQE
