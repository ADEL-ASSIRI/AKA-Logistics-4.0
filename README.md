# Supplementary Files S1–S4
*Provably Secure Three-Party Authentication for Logistics 4.0* (revised version)

| File | Content | Command | Expected result |
|---|---|---|---|
| S1_reference_implementation.py | Executable specification of the revised protocol (Python ≥ 3.9, `pip install cryptography`) | `python3 S1_reference_implementation.py` | Every line starts with `[ok]`; the last line reports message sizes `[256, 808, 392, 392, 520, 128] total = 2496` |
| S2_proverif_model.pv | ProVerif model (challenge mode, phase-1 compromise of `snk`, `K_T`, `K_O`) | `proverif S2_proverif_model.pv` | All `attacker(...)` queries (phase 0 and phase 1) and all five `inj-event` queries report `true` (Table 8) |
| S3_scyther_model.spdl | Scyther model with the standard Diffie–Hellman helper protocol | Scyther GUI: *Verify → Verify protocol*; repeat with *Settings → Adversary model → long-term key reveal after claim* (CLI `--LKRafter=1`) | All claims `Ok` (Table 9) |
| S4_evaluation.py | Computes every number in Tables 12–19 and draws Figures 4–10 | `python3 S4_evaluation.py figs` (needs matplotlib) ; `python3 S4_evaluation.py --bench` for a host micro-benchmark | JSON with the values printed in the paper; PDF figures in `figs/` |

## What each part of the paper relies on
* Correctness of the message flow (Section 4.4, Table 6): S1.
* Symbolic secrecy, injective agreement and forward secrecy (Sections 5.3–5.4): S2, S3.
* All performance numbers (Section 6): S4, with the per-operation timings of Table 11 as the only measured input. To re-measure on your own devices, replace the dictionary `T` at the top of S4 and rerun it.

## Recommended versions
ProVerif 2.05, Scyther v1.1.3, Python 3.12, cryptography 46, matplotlib 3.x, MIRACL Core v7.0 (device benchmarks).
