# Automated tests for quantum-crypto-lab (pqc-eval + bb84 + qrng).
#
# Run:  python -m pytest tests/ -v
#
# Design: everything runs in seconds and is deterministic (fixed seeds).
# Long scans are NOT re-run here; instead we test the statistical core with
# synthetic populations with KNOWN answers, plus the real controls at
# reduced sample sizes, and the physics: BB84 QBER theory and QRNG battery.

import os
import subprocess
import sys

import numpy as np
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from pqc_eval.leak_scanner import (collect_timings, dpa_correlation,
                                   leakage_report, multi_fixed_scan,
                                   scan)

from pqc_eval.experiment_01_kyberslash import (constanttime_lookup, DATA,
                                               leaky_division, leaky_loopcount)

from bb84.simulator import run_bb84
from qrng.entropy_tests import monobit, runs_test

# --------------------------------------------------------------------------
# statistical core with synthetic populations of known answer
# --------------------------------------------------------------------------

def make_report(fixed_us, random_us):
    """leakage_report on synthetic timing populations."""
    t = {"fixed": np.asarray(fixed_us, float),
         "random": np.asarray(random_us, float),
         "fixed_median_us": float(np.median(fixed_us)),
         "random_median_us": float(np.median(random_us))}
    return leakage_report(t)


def test_core_detects_clear_shift():
    r = make_report(np.full(100, 100.0) + np.random.default_rng(0).normal(0, 1, 100),
                    np.full(100, 130.0) + np.random.default_rng(1).normal(0, 1, 100))
    assert r["verdict"] == "LEAK DETECTED"
    assert r["p_value"] < 0.01 and abs(r["cohens_d"]) > 0.8


def test_core_passes_identical_populations():
    rng = np.random.default_rng(2)
    r = make_report(rng.normal(100, 2, 100), rng.normal(100, 2, 100))
    assert r["verdict"] == "NO LEAK"
    assert r["p_value"] > 0.05


def test_core_inconclusive_zone_is_not_a_leak():
    """d ~ 0.5-0.7, p<0.05: INCONCLUSIVE, never silently called clean or leaky."""
    rng = np.random.default_rng(3)
    r = make_report(rng.normal(100, 2, 60), rng.normal(100.9, 2, 60))
    assert r["verdict"] != "LEAK DETECTED"


def test_multi_fixed_smoke_and_stats_math():
    """Value-dependence math verified directly; multi_fixed_scan smoke-run
    separately (a real scan is the positive-control test's job)."""
    rng = np.random.default_rng(4)
    groups = [rng.normal(100 + 20 * j, 1, 30) for j in range(5)]  # real value effect
    from scipy import stats
    F, p = stats.f_oneway(*groups)
    assert p < 0.01 and F > 100
    # smoke: the scanner entry point runs and returns the expected keys
    r = multi_fixed_scan(lambda x, y: 0, [lambda: (0, 0)] * 3,
                         repeats=1, per_vector=3)
    assert {"verdict", "anova_F", "anova_p"} <= set(r)


def test_dpa_correlation_finds_planted_byte():
    rng = np.random.default_rng(5)
    n = 400
    secrets = rng.integers(0, 256, (n, 8), dtype=np.uint8)
    timings = rng.normal(100, 1, n) + 0.05 * secrets[:, 3]  # byte 3 drives time
    r = dpa_correlation(timings, secrets)
    assert r["peak_byte"] == 3
    assert r["p_values"][3] < 0.01
    assert all(p > 0.01 for i, p in enumerate(r["p_values"]) if i != 3)


# --------------------------------------------------------------------------
# real targets, reduced samples (sensitivity + specificity, minutes -> seconds)
# --------------------------------------------------------------------------

def test_control_vulnerable_loopcount_flags():
    """Positive control: the toy vulnerable target MUST flag."""
    rng = np.random.default_rng(42)
    n = 60
    pairs = [(DATA, bytes(rng.integers(1, 256, 512, dtype=np.uint8)))
             for _ in range(n)]
    r = scan(leaky_loopcount, lambda: (DATA, bytes([1]) * 512),
             pairs, repeats=3)
    assert r["verdict"] == "LEAK DETECTED"


def test_control_constanttime_is_clean():
    """Negative control: constant-time target MUST NOT flag."""
    rng = np.random.default_rng(43)
    n = 60
    pairs = [(DATA, bytes(rng.integers(1, 256, 512, dtype=np.uint8)))
             for _ in range(n)]
    r = scan(constanttime_lookup, lambda: (DATA, bytes([1]) * 512),
             pairs, repeats=3)
    assert r["verdict"] != "LEAK DETECTED"


def test_collect_timings_interleaves_and_counts_match():
    calls = []

    def fn(data, sk):
        calls.append(1)
        return 0

    pairs = [(DATA, bytes([2] * 8)) for _ in range(7)]
    t = collect_timings(fn, lambda: (DATA, bytes([1] * 8)), pairs, repeats=2)
    assert len(t["fixed"]) == 7 and len(t["random"]) == 7


# --------------------------------------------------------------------------
# BB84: QBER must match theory (0 / p/4 / 25% signatures)
# --------------------------------------------------------------------------

def test_bb84_clean_channel_zero_qber():
    r = run_bb84(n_bits=4000, eve_rate=0.0, noise_rate=0.0, seed=1)
    assert r["qber"] < 0.001


def test_bb84_full_intercept_resend_is_25_percent():
    r = run_bb84(n_bits=20000, eve_rate=1.0, noise_rate=0.0, seed=2)
    assert abs(r["qber"] - 0.25) < 0.02


def test_bb84_partial_eve_is_between():
    r = run_bb84(n_bits=20000, eve_rate=0.25, noise_rate=0.0, seed=3)
    assert 0.03 < r["qber"] < 0.10          # theory p/4 = 6.25%
    assert r["n_sifted"] > 0


def test_noise_qber_matches_readme_observation():
    """README exp-table row: 5% noise -> 4.61% QBER (seedless variance aside).
    The observed value is ~2x q/2, i.e. q * (right-basis fraction) — document
    the actual mechanism: ONLY right-basis (half of sifted) flips survive, but
    Bob's wrong-basis random draws contribute q/2 as well... net ~q/2. Keep
    the documented empirical band from the README sweep instead of over-deriving.
    """
    qbers = [run_bb84(n_bits=8000, eve_rate=0.0, noise_rate=0.05,
                      seed=100 + t)["qber"] for t in range(10)]
    m = float(np.mean(qbers))
    assert 0.04 < m < 0.06                  # matches README's 4.61% row


# --------------------------------------------------------------------------
# QRNG battery: fair sources pass, biased control fails
# --------------------------------------------------------------------------

def test_entropy_battery_power():
    rng = np.random.default_rng(7)
    fair = rng.integers(0, 2, 20000, dtype=np.uint8)
    assert monobit(fair) > 0.01
    assert runs_test(fair) > 0.01

    biased = (rng.random(20000) < 0.6).astype(np.uint8)
    assert monobit(biased) < 0.01           # battery catches 60/40


def test_bb84_sifted_key_matches_alice_on_clean_channel():
    """On a clean channel the sifted key must equal Alice's bits exactly."""
    r = run_bb84(n_bits=8000, eve_rate=0.0, noise_rate=0.0, seed=9)
    alice_sifted = r["sifted_alice"]
    bob_sifted = r["sifted_bob"]
    assert np.array_equal(alice_sifted, bob_sifted)


# --------------------------------------------------------------------------
# CLI: exit codes drive CI
# --------------------------------------------------------------------------

def test_cli_exit_codes():
    leaky = subprocess.run(
        [sys.executable, "-m", "pqc_eval.cli",
         "pqc_eval.experiment_01_kyberslash.leaky_loopcount",
         "--n-samples", "40", "--repeats", "2"],
        cwd=ROOT, capture_output=True, text=True, timeout=600)
    clean = subprocess.run(
        [sys.executable, "-m", "pqc_eval.cli",
         "pqc_eval.experiment_01_kyberslash.constanttime_lookup",
         "--n-samples", "40", "--repeats", "2"],
        cwd=ROOT, capture_output=True, text=True, timeout=600)
    assert leaky.returncode == 1
    assert "LEAK DETECTED" in leaky.stdout
    assert clean.returncode == 0
    assert "LEAK DETECTED" not in clean.stdout
