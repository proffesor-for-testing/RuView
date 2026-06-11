#!/usr/bin/env python3
# Multi-node CSI capture: separate 0xC5110001 frames by node_id (byte[4]).
# Usage: capture_mn.py <label> <seconds>
import socket, struct, time, json, math, sys
label = sys.argv[1] if len(sys.argv) > 1 else "cap"
secs = float(sys.argv[2]) if len(sys.argv) > 2 else 120
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 5006)); s.settimeout(2)
nodes = {}
end = time.time() + secs
while time.time() < end:
    try: d,_ = s.recvfrom(2048)
    except socket.timeout: continue
    if len(d) < 20 or struct.unpack_from("<I", d, 0)[0] != 0xC5110001: continue
    nid = d[4]
    n_sub = struct.unpack_from("<H", d, 6)[0]
    rssi = struct.unpack_from("<b", d, 16)[0]
    iq = d[20:]; n = min(n_sub, len(iq)//2, 64)
    amp = [math.hypot(struct.unpack_from("<b",iq,2*k)[0], struct.unpack_from("<b",iq,2*k+1)[0]) for k in range(n)]
    nodes.setdefault(nid, []).append({"t": time.time(), "rssi": rssi, "amp": amp})
out = f"/tmp/mn_{label}.json"
json.dump(nodes, open(out, "w"))
print(f"label={label}: " + ", ".join(f"node{k}={len(v)}fr" for k,v in sorted(nodes.items())) + f" -> {out}")
