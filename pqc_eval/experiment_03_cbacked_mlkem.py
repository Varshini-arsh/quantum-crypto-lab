# Experiment 03 — Scan a C-BACKED ML-KEM implementation (pqcrypto, compiled
# Rust/C extension). This is where timing claims get serious: native-speed
# crypto is what real systems ship, and where KyberSlash-class bugs live.
#
# Uses BOTH scanner methods:
#   [A] single-vector fixed-vs-random TVLA (classic)
#   [B] multi-fixed-point ANOVA (our audit-corrected primary method —
#       value-dependence must survive TYPICAL vectors, not just corners)
#
# Target op: ML-KEM-768 decapsulation — the secret-dependent operation an
# attacker would target.

import os
import pickle
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqc_eval.leak_scanner import collect_timings, leakage_report, multi_fixed_scan

from pqcrypto.kem.ml_kem_768 import decaps, encaps, keygen

HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    rng = np.random.default_rng(2026)
    n_random, repeats = 300, 7
    n_vectors, per_vector = 10, 40

    print("=" * 68)
    print("EXPERIMENT 03 - C-backed ML-KEM-768 (pqcrypto native) decaps scan")
    print("=" * 68)

    # correctness sanity: the KEM must actually work before we time it
    pk, sk = keygen()
    ct0, ss0 = encaps(pk)
    assert decaps(sk, ct0) == ss0, "KEM correctness check FAILED"
    print("correctness: encaps/decaps shared secrets MATCH (native KEM works)\n")

    # --- [A] single-vector TVLA: one fixed ciphertext vs many random ones
    ct_fixed, _ = encaps(pk)
    random_cts = [encaps(pk)[0] for _ in range(n_random)]

    def decap(sk_, ct_):
        decaps(sk_, ct_)

    t = collect_timings(decap, lambda: (sk, ct_fixed),
                        [(sk, c) for c in random_cts], repeats=repeats)
    ra = leakage_report(t)
    print("[A] single-vector fixed-vs-random TVLA")
    for k in ("verdict", "welch_t", "p_value", "cohens_d",
              "fixed_median_us", "random_median_us", "timing_spread_ratio"):
        print(f"    {k:22s} {ra[k]}")
    print()

    # --- [B] multi-fixed-point ANOVA: 10 TYPICAL fixed ciphertexts
    fixed_makers = []
    for _ in range(n_vectors):
        ct_j, _ss = encaps(pk)
        fixed_makers.append(lambda ct_j=ct_j: (sk, ct_j))

    rb = multi_fixed_scan(decap, fixed_makers, repeats=repeats,
                          per_vector=per_vector)
    print("[B] multi-fixed-point ANOVA (10 typical ciphertexts)")
    for k in ("verdict", "anova_F", "anova_p", "spread_ratio"):
        print(f"    {k:22s} {rb[k]}")
    print(f"    {'vector_means_us':22s} {rb['vector_means_us']}")
    print()

    print("=" * 68)
    print("VERDICT")
    print("=" * 68)
    print(f"  [A] {ra['verdict']}   [B] {rb['verdict']}")
    clean = (ra["verdict"] != "LEAK DETECTED"
             and rb["verdict"] == "NO VALUE DEPENDENCE")
    print(f"\n  C-backed ML-KEM-768 decaps at this resolution: "
          f"{'CLEAN (no detectable timing leak)' if clean else 'SEE ABOVE'}")
    print("  (clean is the expected result for a hardened native build;")
    print("   our scanner's negative control now extends to production code)")

    with open(os.path.join(HERE, "exp03_result.pkl"), "wb") as f:
        pickle.dump({"single": ra, "anova": rb,
                     "fixed_A": t["fixed"], "random_A": t["random"]}, f)
    return 0


if __name__ == "__main__":
    sys.exit(main())
