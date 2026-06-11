#!/usr/bin/env python3
# Multi-node field-model residual occupancy.
# Per node: learn empty baseline mean + top-K environmental eigenmodes,
# project them out of test frames -> residual (body perturbation) energy.
# Combine across nodes. Compare held-out empty vs occupied (still / moving).
import json, sys
import numpy as np

def load(label):
    d = json.load(open(f"/tmp/mn_{label}.json"))
    return {int(k): np.array([f["amp"] for f in v], dtype=float) for k, v in d.items()}

K = int(sys.argv[1]) if len(sys.argv) > 1 else 12

base = load("baseline")
models = {}
test_empty = {}
for nid, A in base.items():
    sp = int(len(A)*0.6)
    train, te = A[:sp], A[sp:]
    mean = train.mean(0)
    Xc = train - mean
    cov = (Xc.T @ Xc)/(max(len(train)-1,1))
    ev, V = np.linalg.eigh(cov)
    V = V[:, np.argsort(ev)[::-1]]            # descending modes
    models[nid] = (mean, V)
    test_empty[nid] = te

def resid_per_node(A, nid, K):
    mean, V = models[nid]
    Xc = A - mean
    Vk = V[:, :K]
    R = Xc - Xc @ Vk @ Vk.T
    return (R**2).sum(1).mean()

def combined(captures_by_node, K):
    # per-node residual energy, then aggregate across nodes (max & mean)
    per = {nid: resid_per_node(A, nid, K) for nid, A in captures_by_node.items() if nid in models}
    vals = list(per.values())
    return per, (max(vals) if vals else 0), (sum(vals)/len(vals) if vals else 0)

datasets = {"test_empty": test_empty}
for lbl in ["occstill", "occmoving"]:
    try: datasets[lbl] = load(lbl)
    except FileNotFoundError: pass

print(f"=== multi-node residual occupancy (K={K} modes removed per node) ===")
print(f"{'capture':12} " + "  ".join(f"node{n}" for n in sorted(models)) + "   MAX     MEAN")
ref_max = None
for lbl, caps in datasets.items():
    per, mx, mn = combined(caps, K)
    if lbl == "test_empty": ref_max = mx
    pernode = "  ".join(f"{per.get(n,0):5.1f}" for n in sorted(models))
    ratio = f"  ({mx/ref_max:.2f}x empty)" if ref_max else ""
    print(f"{lbl:12} {pernode}   {mx:6.1f}  {mn:6.1f}{ratio}")
