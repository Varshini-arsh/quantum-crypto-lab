# Experiment 05 — Scan the LIBOQS native ML-KEM-768 (the reference open-source
# implementation real systems build on; where KyberSlash-class bugs live).
#
# Same protocol as experiment 03 (pqcrypto C-backed build), so results are
# directly comparable across three implementation stacks:
#   01: pure-Python toy patterns   02: kyber_py (Python ref)   03: pqcrypto (C)
#   05: liboqs (C, NIST submission reference code)  <- this experiment
#
# Uses BOTH scanner methods:
#   [A] single-vector fixed-vs-random TVLA (classic)
#   [B] multi-fixed-point ANOVA (audit-corrected primary method —
#       value-dependence must survive TYPICAL ciphertexts, not just corners)
#
# Target op: ML-KEM-768 decapsulation — the secret-dependent operation an
# attacker would target.

import os
import pickle
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqc_eval.leak_scanner import collect_timings, leakage_report, multi_fixed_scan

import oqs

HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    rng = np.random.default_rng(2026)
    n_random, repeats = 300, 7
    n_vectors, per_vector = 10, 40

    print("=" * 68)
    print("EXPERIMENT 05 - liboqs native ML-KEM-768 decaps scan")
    print("=" * 68)
    print(f"liboqs version: {oqs.oqs_version()}, "
          f"ML-KEM-768 enabled: {'ML-KEM-768' in oqs.get_enabled_kem_backends() if hasattr(oqs, 'get_enabled_kem_backends') else 'assumed (correctness check below)'}")

    # correctness sanity: the KEM must actually work before we time it
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        pk = kem.generate_keypair()
        ct0, ss0 = kem.encap_secret(pk)
        assert kem.decap_secret(ct0) == ss0, "KEM correctness check FAILED"
    print("correctness: encap/decap shared secrets MATCH (liboqs KEM works)\n")

    def decap(sk_kem, ct):
        sk_kem.decap_secret(ct)

    # --- [A] single-vector TVLA: one fixed ciphertext vs many random ones ---
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        sk = kem.generate_keypair()
        ct_fixed, _ = kem.encap_secret(pk)
        random_cts = []
        for _ in range(n_random):
            with oqs.KeyEncapsulation("ML-KEM-768") as tmp:
                pk_r = tmp.generate_keypair()
                random_cts.append(tmp.encap_secret(pk_r)[0])

        fixed_maker = lambda: (kem, ct_fixed)
        t = collect_timings(decap, fixed_maker,
                            [(kem, c) for c in random_cts], repeats=repeats)
        ra = leakage_report(t)
        print("[A] single-vector fixed-vs-random TVLA")
        for k in ("verdict", "welch_t", "p_value", "cohens_d",
                  "fixed_median_us", "random_median_us", "timing_spread_ratio"):
            print(f"    {k:22s} {ra[k]}")
        print()

        # --- [B] multi-fixed-point ANOVA: 10 TYPICAL fixed ciphertexts ------
        fixed_makers = []
        for _ in range(n_vectors):
            ct_j, _ss = kem.encap_secret(pk)
            fixed_makers.append(lambda ct_j=ct_j: (kem, ct_j))

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
    print(f"\n  liboqs ML-KEM-768 decaps at this resolution: "
          f"{'CLEAN (no detectable timing leak)' if clean else 'SEE ABOVE'}")

    with open(os.path.join(HERE, "exp05_result.pkl"), "wb") as f:
        pickle.dump({"impl": f"liboqs {oqs.oqs_version()} ML-KEM-768.decaps",
                     "single": ra, "anova": rb,
                     "fixed_A": t["fixed"], "random_A": t["random"]}, f)
    return 0


if __name__ == "__main__":
    sys.exit(main())
