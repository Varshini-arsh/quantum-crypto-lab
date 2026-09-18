# Experiment 02 — Scan a REAL post-quantum implementation: kyber_py ML-KEM.

# Experiment 01 proved the scanner works (sensitivity + specificity).
# Now we point it at production code: kyber_py's ML-KEM-768 key
# decapsulation — the exact operation a real attacker would target.

# Design:
#   Population A (fixed): the SAME (ciphertext, secret key) pair every time.
#   Population B (random): fresh random ciphertexts against the SAME key.
#
#   For a constant-time decaps: no separation => NO LEAK.
#   For a value-dependent decaps: separation => LEAK.
#
#   The secret key NEVER changes between populations — so any timing
#   difference is attributable to the ciphertext/key interaction, which is
#   precisely the KyberSlash attack surface.

import os
import pickle
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqc_eval.leak_scanner import scan

from kyber_py.ml_kem import ML_KEM_768


def main() -> int:
    rng = np.random.default_rng(7)
    n_inputs, repeats = 150, 5

    print("=" * 66)
    print("EXPERIMENT 02 - Real ML-KEM-768 decapsulation timing scan")
    print("=" * 66)
    print(f"impl: kyber_py ML_KEM_768 (obj {id(ML_KEM_768) % 10_000}) | "
          f"{n_inputs} random inputs x {repeats} reps (median)\n")

    # Real keypair + one real encapsulation to build the fixed vector.
    # kyber_py API: keygen() -> (ek, dk); encaps(ek) -> (ss, ct); decaps(dk, ct)
    ek, dk = ML_KEM_768.keygen()
    _ss, ct_fixed = ML_KEM_768.encaps(ek)

    fixed_pair = lambda: (dk, ct_fixed)  # same content every call

    random_cts = [ML_KEM_768.encaps(ek)[1] for _ in range(n_inputs)]

    def decap(d, c):
        ML_KEM_768.decaps(d, c)

    print("[scan] ML-KEM-768.decaps (kyber_py, pure-python reference)")
    t2 = scan.__wrapped__(decap, fixed_pair, [(dk, c) for c in random_cts],
                          repeats=repeats) if hasattr(scan, "__wrapped__") else None
    from pqc_eval.leak_scanner import collect_timings, leakage_report
    t2 = collect_timings(decap, fixed_pair, [(dk, c) for c in random_cts],
                         repeats=repeats)
    r = leakage_report(t2)
    for k in ("verdict", "welch_t", "p_value", "cohens_d",
              "fixed_median_us", "random_median_us", "timing_spread_ratio"):
        print(f"    {k:22s} {r[k]}")

    # Persist for plotting/posting (report + raw samples)
    out = {"impl": "kyber_py ML_KEM_768.decaps", "report": r,
           "fixed": t2["fixed"], "random": t2["random"]}
    with open(os.path.join(os.path.dirname(__file__), "exp02_result.pkl"), "wb") as f:
        pickle.dump(out, f)

    print("\nVERDICT:", r["verdict"])
    print("(pure-python reference is NOT constant-time memory-access-wise;")
    print(" a LEAK here is expected and is exactly what the scanner should see,")
    print(" production C/ASM builds are the ones that must come back clean.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
