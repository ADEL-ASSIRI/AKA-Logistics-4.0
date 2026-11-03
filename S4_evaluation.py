#!/usr/bin/env python3
"""
S4 - Single source of truth for every performance number and figure in the
revised manuscript (Section 6). All values are derived from:
  (i)  the per-operation timings measured on the testbed (Table 5),
  (ii) the operation counts of the revised protocol (Table 6), and
  (iii) the message formats of Table 8.
Run:  python3 S4_evaluation.py            -> prints all numbers, writes figures to ./figs
      python3 S4_evaluation.py --bench    -> micro-benchmark of P-256 / SHA-256 on this host
"""
import sys, os, json

# ---------------- (i) measured per-operation timings, ms (Table 5) ----------
T = {
    "phone":  dict(mul=0.415, add=0.045,  scalar=0.835, hash=0.674),
    "rpi":    dict(mul=0.216, add=0.327,  scalar=0.479, hash=0.896),
    "laptop": dict(mul=0.450, add=0.0021, scalar=0.019, hash=0.154),
}
# platform used for each entity
PLATFORM = {"OD": "phone", "ET": "rpi", "CS": "laptop"}

# ---------------- (ii) operation counts of the revised protocol --------------
# mul = elliptic-curve point (scalar-by-point) multiplication on P-256
OPS = {
    "OD": dict(mul=2, add=0, scalar=0, hash=3, xor=1),   # aP, aY_C ; V1, Z_O, V4
    "ET": dict(mul=2, add=0, scalar=0, hash=3, xor=0),   # tP, tY_C ; V2, Z_T, Z'_T
    "CS": dict(mul=3, add=0, scalar=0, hash=8, xor=1),   # cP, cX_T, cX_O ; K_O,V1,K_T,V2,Z_T,Z_O,V4,Z'_T
}
KEY_UPDATE_OPS = {"device": dict(mul=0, hash=3), "CS": dict(mul=0, hash=4)}

# ---------------- (iii) message formats (bits) -------------------------------
SZ = dict(PID=128, N=128, PT=264, TS=32, TAG=128, W=128)
MSG = {
    "M0 (ET->OD)": [("PID", "PID_T"), ("N", "N_T")],
    "M1 (OD->CS)": [("PID", "PID_O"), ("PT", "X_O"), ("PID", "PID_T"), ("N", "N_T"), ("TS", "T_1"), ("TAG", "V_1")],
    "M2 (CS->ET)": [("PT", "Y_C"), ("TAG", "V_2")],
    "M3 (ET->CS)": [("PT", "X_T"), ("TAG", "V_3")],
    "M4 (CS->OD)": [("PT", "Y_C"), ("W", "W"), ("TAG", "V_4")],
    "M5 (CS->ET)": [("TAG", "V_5")],
}
SENDER = {"M0 (ET->OD)": ("ET", "OD"), "M1 (OD->CS)": ("OD", "CS"), "M2 (CS->ET)": ("CS", "ET"),
          "M3 (ET->CS)": ("ET", "CS"), "M4 (CS->OD)": ("CS", "OD"), "M5 (CS->ET)": ("CS", "ET")}

STORAGE = {  # bits
    "E-Tag": [("PID_T", 128), ("K_T", 256)],
    "Operator device": [("PID_O", 128), ("K_O", 256)],
    "Cloud server": [("snk (HSM)", 256), ("tag record", 352), ("operator record", 352)],
}
# record = ID (64) + PID_new (128) + PID_old (128) + 32-bit field (key version + status)

# ---------------- power profiles (Table 15) ----------------------------------
PWR = {"ET": dict(active=6.50, tx=2.80, rx=2.20),
       "OD": dict(active=2.80, tx=1.50, rx=1.20),
       "CS": dict(active=45.0, tx=15.0, rx=10.0)}
RATE = 54e6  # bit/s

# ---------------- compared schemes (operation counts, total bits) ------------
SCHEMES = [  # name, mul, add, scalar, hash, bits, messages
    ("Ugochukwu et al.", 6, 2, 4, 12, 5632, 4),
    ("Loske et al.",     4, 0, 2, 18, 2860, 3),
    ("Zhao et al.",      3, 1, 2, 22, 4138, 5),
    ("Alashjaee et al.", 2, 0, 1, 10, 3232, 4),
    ("Yang et al.",      3, 0, 1, 14, 5664, 4),
    ("Gaba et al.",      4, 0, 2, 16, 7400, 4),
]

def cost(ops, plat):
    t = T[plat]
    return sum(ops.get(k, 0) * t[k] for k in ("mul", "add", "scalar", "hash"))

def main(figdir="figs"):
    out = {}
    # computation per entity (device-specific platforms)
    per = {e: cost(OPS[e], PLATFORM[e]) for e in OPS}
    out["per_entity_ms"] = {e: round(v, 3) for e, v in per.items()}
    out["total_device_specific_ms"] = round(sum(per.values()), 3)
    tot_ops = {k: sum(OPS[e][k] for e in OPS) for k in ("mul", "add", "scalar", "hash", "xor")}
    out["total_ops"] = tot_ops
    std_prop = cost(tot_ops, "rpi")
    out["standardized_rpi_ms"] = round(std_prop, 3)

    # communication
    msg_bits = {m: sum(SZ[f] for f, _ in fl) for m, fl in MSG.items()}
    out["msg_bits"] = msg_bits
    total_bits = sum(msg_bits.values())
    out["total_bits"] = total_bits
    out["total_bits_network_only"] = total_bits - msg_bits["M0 (ET->OD)"]

    # storage
    st = {e: sum(b for _, b in v) for e, v in STORAGE.items()}
    out["storage_bits"] = st; out["storage_total_bits"] = sum(st.values())

    # device-specific energy (computation + radio), mJ
    tx = {e: 0 for e in OPS}; rx = {e: 0 for e in OPS}
    for m, b in msg_bits.items():
        s, r = SENDER[m]; tx[s] += b; rx[r] += b
    out["tx_bits"], out["rx_bits"] = tx, rx
    E = {}
    for e in OPS:
        ec = per[e] * PWR[e]["active"]                       # ms * W = mJ
        et = tx[e] / RATE * PWR[e]["tx"] * 1e3
        er = rx[e] / RATE * PWR[e]["rx"] * 1e3
        E[e] = dict(comp=round(ec, 3), tx=round(et, 4), rx=round(er, 4), total=round(ec + et + er, 3))
    out["energy_device_mJ"] = E
    out["energy_session_total_mJ"] = round(sum(v["total"] for v in E.values()), 3)
    out["energy_devices_only_mJ"] = round(E["ET"]["total"] + E["OD"]["total"], 3)

    # comparative (standardized on Raspberry Pi profile)
    p = PWR["ET"]
    def e_std(ms, bits): return ms * p["active"] + bits / RATE * (p["tx"] + p["rx"]) * 1e3
    rows = []
    for name, mul, add, sc, hs, bits, nm in SCHEMES:
        ms = cost(dict(mul=mul, add=add, scalar=sc, hash=hs), "rpi")
        rows.append(dict(name=name, mul=mul, add=add, scalar=sc, hash=hs, ms=round(ms, 3),
                         bits=bits, msgs=nm, energy=round(e_std(ms, bits), 3)))
    prop = dict(name="Proposed", mul=tot_ops["mul"], add=0, scalar=0, hash=tot_ops["hash"],
                ms=round(std_prop, 3), bits=total_bits, msgs=6, energy=round(e_std(std_prop, total_bits), 3))
    for r in rows:
        r["comp_diff_pct"] = round(100 * (r["ms"] - prop["ms"]) / r["ms"], 2)      # >0: proposed cheaper
        r["comm_diff_pct"] = round(100 * (r["bits"] - prop["bits"]) / r["bits"], 2)
        r["energy_diff_pct"] = round(100 * (r["energy"] - prop["energy"]) / r["energy"], 2)
    out["comparison"] = rows + [prop]
    out["key_update"] = dict(
        device_ms_rpi=round(cost(KEY_UPDATE_OPS["device"], "rpi"), 3),
        device_ms_phone=round(cost(KEY_UPDATE_OPS["device"], "phone"), 3),
        cs_ms=round(cost(KEY_UPDATE_OPS["CS"], "laptop"), 3),
        bits=128 + 256 + 128 + 128)
    print(json.dumps(out, indent=1))
    figures(out, figdir)
    return out

def figures(o, d):
    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    os.makedirs(d, exist_ok=True)
    plt.rcParams.update({"font.family": "serif", "font.size": 9, "axes.spines.top": False,
                         "axes.spines.right": False, "pdf.fonttype": 42})
    C1, C2, C3, C4 = "#3b6ea5", "#e08a3c", "#6aa84f", "#9e9e9e"

    # Fig: computation per entity
    ents = ["OD", "ET", "CS"]; lab = ["Operator device\n(Android phone)", "E-Tag\n(Raspberry Pi 5)", "Cloud server\n(laptop)"]
    ecc = [OPS[e]["mul"] * T[PLATFORM[e]]["mul"] for e in ents]
    hsh = [OPS[e]["hash"] * T[PLATFORM[e]]["hash"] for e in ents]
    f, a = plt.subplots(figsize=(4.6, 2.8))
    a.bar(lab, ecc, color=C1, label="EC point multiplications")
    a.bar(lab, hsh, bottom=ecc, color=C2, label="SHA-256 calls")
    for i, e in enumerate(ents):
        a.text(i, ecc[i] + hsh[i] + 0.05, f"{o['per_entity_ms'][e]:.3f} ms", ha="center")
    a.set_ylabel("Computation time (ms)"); a.set_ylim(0, 4.6); a.legend(frameon=False, loc="upper left", ncol=2, fontsize=7.5)
    f.tight_layout(); f.savefig(f"{d}/Fig-CompEntity.pdf"); plt.close(f)

    # Fig: communication per message (stacked by field type)
    names = list(MSG); short = [n.split()[0] + "\n" + n.split()[1][1:-1] for n in names]
    groups = [("PID", "Pseudonyms", C4), ("N", "Nonces", C3), ("PT", "EC points", C1),
              ("TS", "Timestamp", "#b07aa1"), ("TAG", "Authenticators", C2), ("W", "Masked key", "#c9b458")]
    f, a = plt.subplots(figsize=(5.2, 2.9)); bottom = [0] * len(names)
    for key, lbl, col in groups:
        vals = [sum(SZ[k] for k, _ in MSG[n] if k == key) for n in names]
        a.bar(short, vals, bottom=bottom, color=col, label=lbl)
        bottom = [b + v for b, v in zip(bottom, vals)]
    for i, b in enumerate(bottom): a.text(i, b + 12, f"{b}", ha="center")
    a.set_ylabel("Bits"); a.set_ylim(0, 1200); a.legend(frameon=False, ncol=3, fontsize=7, loc="upper right")
    a.set_title(f"Total per session: {o['total_bits']} bits", fontsize=9)
    f.tight_layout(); f.savefig(f"{d}/Fig-CommMsg.pdf"); plt.close(f)

    # Fig: storage
    f, a = plt.subplots(figsize=(4.4, 2.6))
    ks = list(STORAGE); vals = [o["storage_bits"][k] for k in ks]
    a.bar(ks, vals, color=[C3, C3, C1])
    for i, v in enumerate(vals): a.text(i, v + 15, f"{v} bits ({v//8} B)", ha="center")
    a.set_ylabel("Stored bits"); a.set_ylim(0, 1150)
    f.tight_layout(); f.savefig(f"{d}/Fig-Storage.pdf"); plt.close(f)

    rows = o["comparison"]; nm = [r["name"].replace(" et al.", "") for r in rows]
    cols = [C2 if r["name"] == "Proposed" else C1 for r in rows]
    def barfig(key, ylabel, fname, fmt, top):
        f, a = plt.subplots(figsize=(5.2, 2.7))
        v = [r[key] for r in rows]; a.bar(nm, v, color=cols)
        for i, x in enumerate(v): a.text(i, x * 1.01 + top * 0.01, fmt.format(x), ha="center", fontsize=7.5)
        a.set_ylabel(ylabel); a.set_ylim(0, top); plt.xticks(rotation=20)
        f.tight_layout(); f.savefig(f"{d}/{fname}"); plt.close(f)
    barfig("ms", "Standardized computation (ms)", "Fig-CmpComp.pdf", "{:.3f}", 25)
    barfig("bits", "Communication per session (bits)", "Fig-CmpComm.pdf", "{:d}", 8400)
    barfig("energy", "Standardized energy (mJ)", "Fig-CmpEnergy.pdf", "{:.1f}", 165)

    # Fig: trade-off
    f, a = plt.subplots(figsize=(4.6, 3.0))
    for r, c in zip(rows, cols):
        a.scatter(r["ms"], r["bits"], s=45 if r["name"] != "Proposed" else 80, color=c,
                  marker="o" if r["name"] != "Proposed" else "D", zorder=3)
        off = {"Yang et al.": (-22, 6), "Ugochukwu et al.": (6, -11)}.get(r["name"], (5, 4))
        a.annotate(r["name"].replace(" et al.", ""), (r["ms"], r["bits"]), textcoords="offset points",
                   xytext=off, fontsize=7.5)
    a.set_xlabel("Standardized computation (ms)"); a.set_ylabel("Communication (bits)")
    a.set_xlim(8, 24); a.set_ylim(2000, 8000); a.grid(alpha=0.3)
    f.tight_layout(); f.savefig(f"{d}/Fig-Tradeoff.pdf"); plt.close(f)

def bench(n=2000):
    import time, hashlib
    from cryptography.hazmat.primitives.asymmetric import ec
    k = ec.generate_private_key(ec.SECP256R1()); peer = ec.generate_private_key(ec.SECP256R1()).public_key()
    t = time.perf_counter()
    for _ in range(n): k.exchange(ec.ECDH(), peer)
    pm = (time.perf_counter() - t) / n * 1e3
    t = time.perf_counter()
    for _ in range(n): ec.generate_private_key(ec.SECP256R1())
    fb = (time.perf_counter() - t) / n * 1e3
    x = os.urandom(32); t = time.perf_counter()
    for _ in range(n * 50): hashlib.sha256(x).digest()
    hs = (time.perf_counter() - t) / (n * 50) * 1e3
    print(f"P-256 variable-base point mult: {pm:.4f} ms | key generation (fixed-base): {fb:.4f} ms | SHA-256 (32 B): {hs:.5f} ms")

if __name__ == "__main__":
    bench() if "--bench" in sys.argv else main(sys.argv[1] if len(sys.argv) > 1 else "figs")
