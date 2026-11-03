#!/usr/bin/env python3
"""
S1 - Reference implementation of the revised three-party AKA protocol
(Operator Device OD, Cloud Server CS, E-Tag ET) for Logistics 4.0.

Purpose: executable specification. It checks that every value each party
uses is either stored at registration or derivable from stored/received
values, that all verification equations hold, that all three parties end
with the same session key SK, and that tampering with any message is
detected. It also exercises pseudonym/key-version resynchronisation and
the key-update phase.

Dependencies: Python >= 3.9, `cryptography` (P-256 via OpenSSL).
Usage:  python3 S1_reference_implementation.py
"""
import hashlib, os, time, struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

CURVE = ec.SECP256R1()
DELTA_T = 5  # seconds, timestamp window (OD <-> CS only)

def H(*parts: bytes) -> bytes:
    """h(.) = SHA-256 over the length-prefixed concatenation of the inputs."""
    m = hashlib.sha256()
    for p in parts:
        m.update(struct.pack(">H", len(p)) + p)
    return m.digest()

L = lambda x: x[:16]     # [x]_L : left 128 bits
R = lambda x: x[16:]     # [x]_R : right 128 bits
xor = lambda a, b: bytes(i ^ j for i, j in zip(a, b))
rnd = lambda n=16: os.urandom(n)

def keygen():
    sk = ec.generate_private_key(CURVE)
    pub = sk.public_key().public_bytes(serialization.Encoding.X962,
                                       serialization.PublicFormat.CompressedPoint)
    return sk, pub            # pub is the 33-byte (264-bit) compressed point

def dh(sk, peer_pub: bytes) -> bytes:
    # load_from_encoded_point also performs on-curve point validation
    peer = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, peer_pub)
    return sk.exchange(ec.ECDH(), peer)   # x-coordinate of sk*peer

def u32(t: int) -> bytes: return struct.pack(">I", t & 0xFFFFFFFF)
def u32v(v: int) -> bytes: return struct.pack(">I", v)

# ---------------------------------------------------------------- CS
class CloudServer:
    def __init__(self):
        self.snk = rnd(32)              # master secret, kept inside an HSM
        self.db = {}                    # ID -> record (no secret material)
        self.replay_cache = set()
        self.sessions = {}

    def derive(self, ID: bytes, v: int) -> bytes:
        return H(ID, u32v(v), self.snk)  # K = h(ID || v || snk)

    def register(self, kind: str):
        ID = rnd(8)                     # 64-bit identity
        PID = rnd(16)                   # 128-bit pseudonym
        self.db[ID] = dict(kind=kind, pid_new=PID, pid_old=None,
                           v=1, v_pending=None, active=True)
        return ID, PID, self.derive(ID, 1)   # sent over the secure channel

    def lookup(self, pid: bytes, kind: str):
        """Return (ID, record, key) for the presented pseudonym.
        A pseudonym installed by the key-update phase (pid_upd) selects the
        pending key version v' and finalises it; any other pseudonym selects v."""
        for ID, r in self.db.items():
            if r["kind"] != kind or not r["active"]:
                continue
            if r.get("pid_upd") is not None and pid == r["pid_upd"]:
                r["v"], r["v_pending"] = r["v_pending"], None
                r["pid_old"], r["pid_new"], r["pid_upd"] = None, pid, None
                return ID, r, self.derive(ID, r["v"])
            if pid in (r["pid_new"], r["pid_old"]):
                return ID, r, self.derive(ID, r["v"])
        return None, None, None

    # M1 -> M2
    def on_M1(self, M1, now):
        PIDO, XO, PIDT, NT, T1, V1 = M1
        if abs(now - T1) > DELTA_T or (PIDO, T1, V1) in self.replay_cache:
            raise ValueError("CS: stale or replayed M1")
        IDO, rO, KO = self.lookup(PIDO, "OD")
        if rO is None: raise ValueError("CS: unknown/revoked operator")
        if L(H(KO, PIDO, XO, PIDT, NT, u32(T1))) != V1:   # cheap checks only, no ECC yet
            raise ValueError("CS: V1 invalid")
        self.replay_cache.add((PIDO, T1, V1))
        IDT, rT, KT = self.lookup(PIDT, "ET")
        if rT is None: raise ValueError("CS: unknown/revoked tag")
        c, YC = keygen()
        V2 = L(H(KT, PIDT, NT, YC))
        self.sessions = dict(c=c, YC=YC, XO=XO, KO=KO, KT=KT, PIDO=PIDO,
                             PIDT=PIDT, NT=NT, T1=T1, IDO=IDO, IDT=IDT)
        return (YC, V2)

    # M3 -> M4, M5
    def on_M3(self, M3):
        XT, V3 = M3
        s = self.sessions
        KTC = dh(s["c"], XT)
        ZT = H(s["KT"], KTC, s["PIDT"], s["NT"], s["YC"], XT)
        if R(ZT) != V3: raise ValueError("CS: V3 invalid")
        SK = L(ZT)
        KOC = dh(s["c"], s["XO"]); del s["c"]           # erase ephemeral scalar
        ZO = H(s["KO"], KOC, s["PIDO"], s["XO"], s["YC"], u32(s["T1"]))
        W = xor(SK, L(ZO)); PIDO_next = R(ZO)
        V4 = L(H(s["KO"], KOC, SK, W, s["YC"]))
        ZT2 = H(s["KT"], SK, XT, s["NT"])
        V5, PIDT_next = L(ZT2), R(ZT2)
        self._roll(s["IDO"], s["PIDO"], PIDO_next)
        self._roll(s["IDT"], s["PIDT"], PIDT_next)
        s["SK"] = SK
        return (s["YC"], W, V4), (V5,)

    def _roll(self, ID, used_pid, nxt):
        r = self.db[ID]
        if used_pid == r["pid_new"]:
            r["pid_old"], r["pid_new"] = r["pid_new"], nxt
        else:                       # device presented the old pseudonym
            r["pid_new"] = nxt

    # key update (U1) and confirmation (U3)
    def key_update_U1(self, ID, SK, K_cur):
        r = self.db[ID]
        v_new = r["v"] + 1
        K_new = self.derive(ID, v_new)
        nU = rnd(16)
        Delta = xor(K_new, H(SK, K_cur, nU))
        Z = H(K_new, SK, nU, Delta)
        r["v_pending"] = v_new
        r["pid_upd"] = L(H(K_new, nU))          # pseudonym bound to the new key
        self._upd = (ID, R(Z))
        return (nU, Delta, L(Z))

    def key_update_U3(self, tau2):
        ID, expect = self._upd
        if tau2 != expect: raise ValueError("CS: bad update ack")
        r = self.db[ID]
        r["v"], r["v_pending"] = r["v_pending"], None
        r["pid_old"], r["pid_new"], r["pid_upd"] = None, r["pid_upd"], None

    def revoke(self, ID): self.db[ID]["active"] = False

# ---------------------------------------------------------------- devices
class ETag:
    def __init__(self, PID, K): self.PID, self.K = PID, K
    def M0(self):
        self.NT = rnd(16); return (self.PID, self.NT)
    def on_M2(self, M2):
        YC, V2 = M2
        if L(H(self.K, self.PID, self.NT, YC)) != V2:      # explicit check of CS
            raise ValueError("ET: V2 invalid (CS not authenticated)")
        t, XT = keygen()
        KTC = dh(t, YC); del t                             # erase ephemeral
        ZT = H(self.K, KTC, self.PID, self.NT, YC, XT)
        self._SK, self._XT = L(ZT), XT
        return (XT, R(ZT))
    def on_M5(self, M5):
        (V5,) = M5
        Z = H(self.K, self._SK, self._XT, self.NT)
        if L(Z) != V5: raise ValueError("ET: V5 invalid")
        self.PID = R(Z); self.SK = self._SK; del self.NT
        return self.SK
    def on_U1(self, U1, SK):
        nU, Delta, tau1 = U1
        K_new = xor(Delta, H(SK, self.K, nU))
        Z = H(K_new, SK, nU, Delta)
        if L(Z) != tau1: raise ValueError("device: bad update")
        self.K, self.PID = K_new, L(H(K_new, nU))   # new key + new pseudonym
        return R(Z)

class OperatorDevice(ETag):
    def M1(self, M0, now):
        PIDT, NT = M0
        self.a, self.XO = keygen(); self.T1 = now
        V1 = L(H(self.K, self.PID, self.XO, PIDT, NT, u32(now)))
        return (self.PID, self.XO, PIDT, NT, now, V1)
    def on_M4(self, M4):
        YC, W, V4 = M4
        KOC = dh(self.a, YC); del self.a
        ZO = H(self.K, KOC, self.PID, self.XO, YC, u32(self.T1))
        SK = xor(W, L(ZO))
        if L(H(self.K, KOC, SK, W, YC)) != V4:
            raise ValueError("OD: V4 invalid (CS not authenticated)")
        self.PID = R(ZO); self.SK = SK
        return SK

# ---------------------------------------------------------------- tests
def run_session(cs, od, et, drop=None, tamper=None):
    now = int(time.time())
    m0 = et.M0()
    m1 = od.M1(m0, now)
    if tamper == "M1": m1 = m1[:5] + (xor(m1[5], b"\x01" + bytes(15)),)
    m2 = cs.on_M1(m1, now)
    if tamper == "M2": m2 = (m2[0], xor(m2[1], b"\x01" + bytes(15)))
    m3 = et.on_M2(m2)
    if tamper == "M3": m3 = (m3[0], xor(m3[1], b"\x01" + bytes(15)))
    m4, m5 = cs.on_M3(m3)
    if tamper == "M4": m4 = (m4[0], xor(m4[1], b"\x01" + bytes(15)), m4[2])
    sk_od = None if drop == "M4" else od.on_M4(m4)
    sk_et = None if drop == "M5" else et.on_M5(m5)
    return cs.sessions["SK"], sk_od, sk_et

def main():
    cs = CloudServer()
    IDT, PIDT, KT = cs.register("ET"); et = ETag(PIDT, KT)
    IDO, PIDO, KO = cs.register("OD"); od = OperatorDevice(PIDO, KO)

    sk_cs, sk_od, sk_et = run_session(cs, od, et)
    assert sk_cs == sk_od == sk_et, "session keys differ"
    print("[ok] honest run: all three parties hold the same 128-bit SK")

    for m in ("M1", "M2", "M3", "M4"):
        try: run_session(cs, od, et, tamper=m); print(f"[FAIL] tampered {m} accepted")
        except ValueError as e: print(f"[ok] tampered {m} rejected -> {e}")

    # replay of M1
    now = int(time.time()); m1 = od.M1(et.M0(), now); cs.on_M1(m1, now)
    try: cs.on_M1(m1, now); print("[FAIL] replay accepted")
    except ValueError as e: print(f"[ok] replayed M1 rejected -> {e}")

    # lost M5 / lost M4 -> devices keep old pseudonym, CS keeps old+new
    sk_cs, sk_od, _ = run_session(cs, od, et, drop="M5")
    sk_cs, sk_od, sk_et = run_session(cs, od, et)
    assert sk_cs == sk_od == sk_et
    print("[ok] resynchronised after a lost M5 (tag reused its old pseudonym)")
    run_session(cs, od, et, drop="M4")
    sk_cs, sk_od, sk_et = run_session(cs, od, et)
    assert sk_cs == sk_od == sk_et
    print("[ok] resynchronised after a lost M4 (operator reused its old pseudonym)")

    # key update for the operator device, acknowledgement delivered
    U1 = cs.key_update_U1(IDO, sk_od, od.K); cs.key_update_U3(od.on_U1(U1, sk_od))
    sk_cs, sk_od, sk_et = run_session(cs, od, et)
    assert sk_cs == sk_od == sk_et
    print("[ok] operator key updated (ack delivered) and next session succeeds")
    # key update for the tag, acknowledgement lost
    U1 = cs.key_update_U1(IDT, sk_et, et.K)
    _tau2 = et.on_U1(U1, sk_et)            # ack lost: CS keeps v and v' pending
    sk_cs, sk_od, sk_et = run_session(cs, od, et)
    assert sk_cs == sk_od == sk_et
    print("[ok] tag key updated, ack lost: CS selects v' from the tag's pseudonym")
    # key update for the tag, U1 itself lost: tag still holds the old key
    U1 = cs.key_update_U1(IDT, sk_et, et.K)
    sk_cs, sk_od, sk_et = run_session(cs, od, et)
    assert sk_cs == sk_od == sk_et
    print("[ok] tag key update message lost: old key still accepted")

    # revocation
    cs.revoke(IDT)
    try: run_session(cs, od, et); print("[FAIL] revoked tag accepted")
    except ValueError as e: print(f"[ok] revoked tag rejected -> {e}")

    # sizes (bits) of the messages actually produced
    cs2 = CloudServer(); a,b,c_ = cs2.register("ET"); et2 = ETag(b, c_)
    a,b,c_ = cs2.register("OD"); od2 = OperatorDevice(b, c_)
    now = int(time.time()); m0 = et2.M0(); m1 = od2.M1(m0, now)
    m2 = cs2.on_M1(m1, now); m3 = et2.on_M2(m2); m4, m5 = cs2.on_M3(m3)
    bits = lambda m: sum(32 if isinstance(x, int) else 8*len(x) for x in m)
    sizes = [bits(m) for m in (m0, m1, m2, m3, m4, m5)]
    print("[info] message sizes M0..M5 (bits):", sizes, "total =", sum(sizes))

if __name__ == "__main__":
    main()
