# Entropy certification battery (accessible NIST-STS-style tests).
#
# Tests, each returning a p-value where applicable:
#   1. Monobit frequency  — proportion of 1s consistent with p=0.5
#   2. Runs test          — run count matches iid fair-coin expectation
#   3. Serial (pairs)     — 00/01/10/11 chi-square uniformity
#   4. Lag-1 autocorrelation — no correlation between adjacent bits
#   5. Shannon entropy    — empirical H per bit (report, not p-value)
#
# Certificate design (controls methodology, same as pqc_eval):
#   quantum bits (Aer)  -> MUST PASS
#   classical PRNG      -> MUST PASS
#   biased source 60/40 -> MUST FAIL  (proves the battery has power)

import math
import os
import sys

import numpy as np
from scipy import stats as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def monobit(bits):
    """Frequency test: binomial test vs p=0.5."""
    n = len(bits)
    ones = int(bits.sum())
    return st.binomtest(ones, n, 0.5).pvalue


def runs_test(bits):
    """Wald-Wolfowitz runs test on a binary sequence."""
    x = 2 * bits.astype(int) - 1          # map to +/-1
    runs = 1 + int(np.sum(x[1:] != x[:-1]))
    n = len(x)
    n1 = int((x > 0).sum())
    n0 = n - n1
    if n1 == 0 or n0 == 0:
        return 0.0
    mu = 2 * n1 * n0 / n + 1
    var = 2 * n1 * n0 * (2 * n1 * n0 - n) / (n ** 2 * (n - 1))
    z = (runs - mu) / math.sqrt(var)
    return 2 * (1 - st.norm.cdf(abs(z)))


def serial_pairs(bits):
    """Chi-square uniformity over bit pairs 00/01/10/11."""
    pairs = bits[:-1] * 2 + bits[1:]
    counts = np.bincount(pairs, minlength=4).astype(float)
    # pairs overlap -> adjacent pairs are dependent; use non-overlapping
    b = bits[0:2 * (len(bits) // 2)].reshape(-1, 2)
    idx = b[:, 0] * 2 + b[:, 1]
    counts = np.bincount(idx, minlength=4).astype(float)
    expected = np.full(4, counts.sum() / 4)
    return st.chisquare(counts, expected).pvalue


def lag1_autocorr(bits):
    """Lag-1 autocorrelation of the +/-1 sequence."""
    x = 2 * bits.astype(float) - 1
    n = len(x)
    r = float(np.corrcoef(x[:-1], x[1:])[0, 1])
    z = r * math.sqrt(n - 1)              # approx under H0 (rho=0)
    return 2 * (1 - st.norm.cdf(abs(z))), r


def shannon_entropy(bits):
    p = float(bits.mean())
    if p in (0.0, 1.0):
        return 0.0
    return float(-(p * math.log2(p) + (1 - p) * math.log2(1 - p)))


def certificate(bits, name):
    p_freq = monobit(bits)
    p_runs = runs_test(bits)
    p_serial = serial_pairs(bits)
    p_ac, r = lag1_autocorr(bits)
    H = shannon_entropy(bits)
    passed = min(p_freq, p_runs, p_serial, p_ac) > 0.01
    return {
        "name": name,
        "n_bits": len(bits),
        "monobit_p": p_freq,
        "runs_p": p_runs,
        "serial_p": p_serial,
        "autocorr_p": p_ac,
        "lag1_r": r,
        "entropy_bits": H,
        "verdict": "PASS" if passed else "FAIL",
    }


def main():
    from qrng.generator import classical_bits, quantum_bits

    N = 40_000
    print(f"generating {N} bits per source ...")
    sources = [
        ("QUANTUM (Aer Hadamard)", quantum_bits(N)),
        ("CLASSICAL (numpy PCG64)", classical_bits(N, seed=123)),
        ("BIASED control 60/40  ",
         (np.random.default_rng(5).random(N) < 0.6).astype(np.uint8)),
    ]

    print(f"\n{'source':26s} {'n':>7s} {'freq_p':>9s} {'runs_p':>9s} "
          f"{'serial_p':>9s} {'ac_p':>9s} {'H(bits)':>8s}  verdict")
    print("-" * 92)
    results = []
    for name, bits in sources:
        r = certificate(bits, name)
        results.append(r)
        print(f"{r['name']:26s} {r['n_bits']:7d} {r['monobit_p']:9.4f} "
              f"{r['runs_p']:9.4f} {r['serial_p']:9.4f} {r['autocorr_p']:9.4f} "
              f"{r['entropy_bits']:8.5f}  {r['verdict']}")

    print("\n" + "=" * 92)
    q_ok = results[0]["verdict"] == "PASS"
    c_ok = results[1]["verdict"] == "PASS"
    b_fail = results[2]["verdict"] == "FAIL"
    print(f"battery validated (quantum PASS, classical PASS, biased FAIL): "
          f"{q_ok and c_ok and b_fail}")


if __name__ == "__main__":
    main()
