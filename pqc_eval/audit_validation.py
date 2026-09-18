# VALIDATION AUDIT — adversarial self-review of the scanner and claims.
#
# A skeptical reviewer would attack our Day-1 results on four grounds.
# Each attack is implemented here as an experiment; the scanner is strong
# only if it survives all four.
#
# ATTACK 1 (reproducibility): different seed -> same verdicts?
# ATTACK 2 (extreme-corner artifact): our fixed vector (all 0x01 bytes) is
#   the timing MINIMUM for the loop-count leak, so the 5.5x gap may be an
#   artifact of choosing the extreme corner. Fix: repeat with 10 TYPICAL
#   fixed vectors (random draws) — the leak must still separate.
# ATTACK 3 (statistics): Welch's t-test assumes ~normal, independent samples;
#   timings are skewed/autocorrelated. Fix: confirm with Mann-Whitney U
#   (nonparametric) + a permutation test (gold standard).
# ATTACK 4 (power): a single fixed vector gives one comparison. Multi-
#   fixed-point variance decomposition asks: does input VALUE explain timing
#   variance better than noise? (one-way ANOVA F across 10 fixed vectors vs
#   within-vector spread) — leaks must survive even with typical vectors.

import os
import sys

import numpy as np
from scipy import stats

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqc_eval.leak_scanner import _measure_us
from pqc_eval.experiment_01_kyberslash import (
    DATA, KEY_LEN, leaky_division, leaky_loopcount, constanttime_lookup)

RNG = np.random.default_rng(1234)  # DIFFERENT seed from experiment 01 (42)


def paired_samples(fn, fixed_secret, n_random=120, reps=3):
    """Interleaved A/B timing samples (same design as the scanner)."""
    fixed, rnd = [], []
    pairs = [(DATA, bytes(RNG.integers(1, 256, KEY_LEN, dtype=np.uint8)))
             for _ in range(n_random)]
    for i in range(n_random):
        rnd.append(float(np.median([_measure_us(fn, *pairs[i])
                                    for _ in range(reps)])))
        fixed.append(float(np.median([_measure_us(fn, DATA, fixed_secret)
                                      for _ in range(reps)])))
    return np.asarray(fixed), np.asarray(rnd)


def full_stats(fixed, rnd):
    """All three tests must agree for a robust verdict."""
    welch = stats.ttest_ind(fixed, rnd, equal_var=False)
    mw = stats.mannwhitneyu(fixed, rnd, alternative="two-sided")
    # permutation test on mean difference (10k shuffles)
    obs = rnd.mean() - fixed.mean()
    pool = np.concatenate([fixed, rnd])
    n = len(fixed)
    perm = np.array([
        pool[RNG.permutation(len(pool))]
        for _ in range(10_000)
    ])
    diffs = np.abs(perm[:, n:].mean(axis=1) - perm[:, :n].mean(axis=1))
    p_perm = float((diffs >= abs(obs)).mean())
    return {
        "welch_p": float(welch.pvalue),
        "mw_p": float(mw.pvalue),
        "perm_p": p_perm,
        "d": (rnd.mean() - fixed.mean()) / pool.std(ddof=1),
        "ratio": rnd.mean() / fixed.mean(),
    }


def attack1_reproducibility():
    print("=" * 68)
    print("ATTACK 1 — Reproducibility (new seed 1234, same protocol)")
    print("=" * 68)
    secrets = [bytes(RNG.integers(1, 256, KEY_LEN, dtype=np.uint8))
               for _ in range(120)]
    ok = True
    for name, fn, expect in [
        ("vulnerable loop-count", leaky_loopcount, "LEAK"),
        ("constant-time lookup", constanttime_lookup, "CLEAN"),
        ("CPython division", leaky_division, "CLEAN"),
    ]:
        fixed = bytes([1]) * KEY_LEN
        f, r = paired_samples(fn, fixed)
        s = full_stats(f, r)
        verdict = ("LEAK" if min(s["welch_p"], s["mw_p"], s["perm_p"]) < 0.01
                   else "CLEAN")
        match = verdict == expect
        ok &= match
        print(f"  {name:24s} welch_p={s['welch_p']:.2e} mw_p={s['mw_p']:.2e} "
              f"perm_p={s['perm_p']:.2e} d={s['d']:6.2f} "
              f"-> {verdict} ({'OK' if match else 'MISMATCH'})")
    print(f"  reproducibility: {'PASS' if ok else 'FAIL'}\n")
    return ok


def attack2_corner_artifact():
    print("=" * 68)
    print("ATTACK 2 — Extreme-corner artifact (10 TYPICAL fixed vectors)")
    print("=" * 68)
    # 10 fixed secrets drawn from the SAME distribution as random ones.
    # If the 'leak' was just our corner-pick, separation must vanish.
    ratios, pvals = [], []
    for j in range(10):
        fixed = bytes(RNG.integers(1, 256, KEY_LEN, dtype=np.uint8))
        f, r = paired_samples(leaky_loopcount, fixed, n_random=80)
        s = full_stats(f, r)
        ratios.append(s["ratio"]); pvals.append(s["welch_p"])
        print(f"  fixed-vector {j+1:2d}: ratio={s['ratio']:5.2f}x  "
              f"welch_p={s['welch_p']:.2e}  d={s['d']:5.2f}")
    all_leak = all(p < 0.01 for p in pvals)
    print(f"  all 10 typical vectors separate: {'PASS' if all_leak else 'FAIL'}")
    print(f"  mean ratio {np.mean(ratios):.2f}x (not just the corner's 5.5x)\n")
    return all_leak


def attack3_statistics():
    print("=" * 68)
    print("ATTACK 3 — Statistical robustness (3 tests must agree)")
    print("=" * 68)
    fixed = bytes([1]) * KEY_LEN
    ok = True
    for name, fn, expect in [
        ("vulnerable loop-count", leaky_loopcount, "LEAK"),
        ("constant-time lookup", constanttime_lookup, "CLEAN"),
    ]:
        f, r = paired_samples(fn, fixed)
        s = full_stats(f, r)
        agree_leak = max(s["welch_p"], s["mw_p"], s["perm_p"])
        agree_clean = min(s["welch_p"], s["mw_p"], s["perm_p"])
        verdict = "LEAK" if agree_leak < 0.01 else ("CLEAN" if agree_clean > 0.05 else "MIXED")
        match = verdict == expect
        ok &= match
        print(f"  {name:24s} welch={s['welch_p']:.1e} MW={s['mw_p']:.1e} "
              f"perm={s['perm_p']:.1e} -> {verdict} "
              f"({'OK' if match else 'MISMATCH'})")
    print(f"  cross-test agreement: {'PASS' if ok else 'FAIL'}\n")
    return ok


def attack4_multifixed_variance():
    print("=" * 68)
    print("ATTACK 4 — Multi-fixed-point variance decomposition (ANOVA)")
    print("=" * 68)
    # 10 typical fixed vectors x 40 samples each, interleaved collection.
    # If secret VALUE drives timing, between-vector variance >> within-vector.
    groups = []
    for j in range(10):
        fixed = bytes(RNG.integers(1, 256, KEY_LEN, dtype=np.uint8))
        samples = [float(np.median([_measure_us(leaky_loopcount, DATA, fixed)
                                    for _ in range(3)]))
                   for _ in range(40)]
        groups.append(samples)
    F, p = stats.f_oneway(*groups)
    between = np.mean([np.mean(g) for g in groups])
    print(f"  ANOVA across 10 typical secrets: F={F:8.1f}  p={p:.2e}")
    print(f"  between-secret mean: {between:.1f} µs")
    print(f"  secret-VALUE explains timing: {'PASS' if p < 0.01 else 'FAIL'}\n")
    return bool(p < 0.01)


def main() -> int:
    print("VALIDATION AUDIT — can our Day-1 claims survive attack?\n")
    r1 = attack1_reproducibility()
    r2 = attack2_corner_artifact()
    r3 = attack3_statistics()
    r4 = attack4_multifixed_variance()
    print("=" * 68)
    print("AUDIT VERDICT")
    print("=" * 68)
    for name, ok in [("reproducibility", r1), ("corner-artifact", r2),
                     ("statistical robustness", r3), ("multi-fixed power", r4)]:
        print(f"  {name:24s} {'PASS' if ok else 'FAIL'}")
    all_ok = r1 and r2 and r3 and r4
    print(f"\n  OVERALL: {'VALIDATED — claims are strong' if all_ok else 'CLAIMS NEED REVISION'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
