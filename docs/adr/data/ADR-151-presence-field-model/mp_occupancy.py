#!/usr/bin/env python3
# Apply RuView's estimate_occupancy algorithm (field_model.rs) to captured CSI:
# covariance of subcarrier amplitudes -> eigenvalues -> count above Marcenko-Pastur
# noise floor. Empty should give ~0 signal eigenvalues; a person >=1.
import json
import numpy as np

def load(label):
    f = json.load(open(f"/tmp/csi_{label}.json"))
    return np.array([fr["amp"] for fr in f], dtype=float)  # [T, n_sc]

def mp_occupancy(A, anchor_noise=None):
    T, n = A.shape
    X = A - A.mean(0, keepdims=True)
    cov = (X.T @ X) / (T - 1)               # [n,n] covariance across subcarriers
    ev = np.linalg.eigvalsh(cov)            # ascending
    pos = np.sort(ev[ev > 1e-10])
    if len(pos) >= 4:
        noise_var = pos[:len(pos)//2].mean()    # bottom-half mean
    elif len(pos):
        noise_var = pos[0]
    else:
        noise_var = 1e-10
    if anchor_noise is not None:
        noise_var = anchor_noise
    ratio = n / float(T)                     # p/n (single link)
    mp_thresh = noise_var * (1.0 + np.sqrt(ratio))**2
    signal_eigs = int((ev > mp_thresh).sum())
    top = float(ev.max() / (noise_var + 1e-12))  # top-eigenvalue / noise (SNR)
    return dict(T=T, signal_eigs=signal_eigs, noise_var=round(noise_var,3),
                mp_thresh=round(mp_thresh,3), top_over_noise=round(top,1),
                top3=[round(float(x),2) for x in ev[::-1][:3]])

# Learn the empty-room noise floor (the field-model anchor)
empty = load("empty")
empty_res = mp_occupancy(empty)
anchor = empty_res["noise_var"]
print("=== self-referential (each capture's own MP threshold) ===")
for lbl in ["empty","occupied_still","occupied_moving"]:
    print(f"{lbl:16}", mp_occupancy(load(lbl)))
print(f"\n=== anchored to EMPTY noise floor ({anchor}) — the field-model way ===")
for lbl in ["empty","occupied_still","occupied_moving"]:
    print(f"{lbl:16}", mp_occupancy(load(lbl), anchor_noise=anchor))
