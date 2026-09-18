# Timing-leak detection for post-quantum crypto implementations.

# Statistical core: TVLA-style (Test Vector Leakage Assessment) fixed-vs-random
# t-test on timing distributions, with interleaved measurement to suppress
# thermal-drift confounds and homogeneous populations on both sides.

from __future__ import annotations

import math
import time

import numpy as np
from scipy import stats


def _measure_us(fn, *args) -> float:
    """Time one call of fn(*args) in microseconds (perf_counter_ns precision)."""
    t0 = time.perf_counter_ns()
    fn(*args)
    return (time.perf_counter_ns() - t0) / 1_000.0


def collect_timings(fn, fixed_input, random_inputs, repeats: int = 5) -> dict:
    """Collect timing samples, TVLA-style, with interleaving.

    Population A (fixed): the SAME input content, a fresh object each call.
    Population B (random): fresh random inputs.

    Design guarantees:
      * Both populations call fn the same number of times, interleaved
        (A,B,A,B,...) so laptop thermal drift affects both equally.
      * A uses a fresh bytes copy every call so object allocation cost
        is identical in both populations.
      * Per-sample timing is a median of `repeats` back-to-back runs.
    """
    fixed_t, random_t = [], []
    n = min(len(random_inputs), 10_000)
    for i in range(n):
        # population B: random input
        b_samples = [_measure_us(fn, *random_inputs[i]) for _ in range(repeats)]
        random_t.append(float(np.median(b_samples)))
        # population A: fixed input, fresh object copy (same content)
        a_samples = [_measure_us(fn, *fixed_input()) for _ in range(repeats)]
        fixed_t.append(float(np.median(a_samples)))

    fixed, rnd = np.asarray(fixed_t), np.asarray(random_t)
    return {
        "fixed": fixed,
        "random": rnd,
        "fixed_median_us": float(np.median(fixed)),
        "random_median_us": float(np.median(rnd)),
    }


def leakage_report(t: dict) -> dict:
    """Compute the leakage verdict from collect_timings output."""
    fixed, rnd = t["fixed"], t["random"]

    # Welch's t-test: do the two populations' timings differ?
    tt = stats.ttest_ind(fixed, rnd, equal_var=False)

    # Effect size (Cohen's d, pooled std)
    nx, ny = len(fixed), len(rnd)
    pooled = math.sqrt(((nx - 1) * fixed.var() + (ny - 1) * rnd.var()) / (nx + ny - 2))
    d = (rnd.mean() - fixed.mean()) / pooled if pooled > 0 else 0.0

    # Range ratio across random inputs (classic KyberSlash signature)
    spread = rnd.max() / rnd.min() if rnd.min() > 0 else float("inf")

    leaky = (tt.pvalue < 0.01) and (abs(d) > 0.8)
    verdict = (
        "LEAK DETECTED"
        if leaky
        else ("INCONCLUSIVE" if (tt.pvalue < 0.05 or abs(d) > 0.5) else "NO LEAK")
    )
    return {
        "verdict": verdict,
        "welch_t": round(float(tt.statistic), 3),
        "p_value": float(tt.pvalue),
        "cohens_d": round(d, 3),
        "fixed_median_us": round(t["fixed_median_us"], 1),
        "random_median_us": round(t["random_median_us"], 1),
        "timing_spread_ratio": round(float(spread), 3),
        "n_fixed": nx,
        "n_random": ny,
    }


def scan(fn, fixed_input_fn, random_inputs, repeats: int = 5) -> dict:
    """One-call API: collect + report.

    fixed_input_fn: zero-arg callable returning a fresh copy of the fixed input
                    (same content every call).
    random_inputs:  list of input tuples, one per sample.
    """
    return leakage_report(collect_timings(fn, fixed_input_fn, random_inputs, repeats))
