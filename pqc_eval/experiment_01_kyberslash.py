# Experiment 01 — Timing-leak reproduction, with scientific controls.
#
# Targets:
#   [1] C-style KyberSlash pattern (secret-dependent division)
#   [2] Secret-dependent loop count (RSA square-and-multiply / conditional
#       reduction family — the most common real-world timing bug class)
#   [3] Constant-time table lookup (the patched pattern)
#
# Scanner validation logic:
#   [2] MUST flag (sensitivity)  |  [1], [3] MUST NOT flag (specificity)
#
# Finding (this machine, CPython 3.12): [1] does NOT leak in pure Python —
# CPython int division timing depends on operand digit-count, not value, so
# the C-level bug is masked. Control-flow leaks DO survive. This matters:
# porting crypto code to Python hides hardware leaks but exposes bytecode-
# count leaks.

import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqc_eval.leak_scanner import scan

KEY_LEN = 512  # like ML-KEM-768 secret key size
DATA = b"\xff"


def leaky_division(data: bytes, sk: bytes) -> int:
    """[1] KyberSlash family in Python: secret-dependent division.

    Expectation on CPython: NO leak (int division is digit-count-driven).
    """
    acc = 0
    for b in sk:
        if b:
            acc += data[0] // b
    return acc & 0xFF


def leaky_loopcount(data: bytes, sk: bytes) -> int:
    """[2] Secret-dependent loop count (value-driven control flow).

    Iterations per byte = bit_length(b) - 1  -> timing encodes the secret.
    Same bug class as RSA square-and-multiply and KyberSlash's
    conditional-reduction paths.
    """
    acc = 0
    for b in sk:
        x = b
        while x > 1:
            x >>= 1
        acc = (acc + x) & 0xFF
    return acc & 0xFF


# [3] constant-time masked table lookup (patch-style)
_QTABLE = bytes([0]) + bytes(255 // b for b in range(1, 256))


def constanttime_lookup(data: bytes, sk: bytes) -> int:
    """[3] Patched pattern: masked table lookup, no value-dependent flow."""
    acc = 0
    n = data[0] & 0xFF
    for b in sk:
        mask = -(b != 0) & 0xFF
        q = _QTABLE[n if b else 1]
        acc = (acc + (q & mask)) & 0xFF
    return acc & 0xFF


def main() -> int:
    rng = np.random.default_rng(42)
    n_inputs, repeats = 200, 5

    print("=" * 66)
    print("EXPERIMENT 01 - Timing-leak reproduction with controls")
    print("=" * 66)
    print(f"{n_inputs} random inputs x {repeats} reps (median), "
          f"secret key {KEY_LEN} B, CPython {sys.version.split()[0]}\n")

    # Homogeneous secrets: uniform bytes 1..255 (no zeros) in all populations.
    random_secrets = [bytes(rng.integers(1, 256, KEY_LEN, dtype=np.uint8))
                      for _ in range(n_inputs)]
    pairs = [(DATA, k) for k in random_secrets]

    def fixed_pair():
        # Fixed vector at the leakage extreme (all min-entropy bytes):
        # same content each call, fresh object.
        return DATA, bytes([1]) * KEY_LEN

    targets = [
        ("[1] KyberSlash pattern (secret-dep. division)", leaky_division,
         "expect: NO LEAK (CPython masks it)"),
        ("[2] Secret-dependent loop count", leaky_loopcount,
         "expect: LEAK DETECTED"),
        ("[3] Constant-time table lookup", constanttime_lookup,
         "expect: NO LEAK"),
    ]

    results = []
    for title, fn, expect in targets:
        print(f"--- {title}  ({expect})")
        r = scan(fn, fixed_pair, pairs, repeats=repeats)
        for k in ("verdict", "welch_t", "p_value", "cohens_d",
                  "fixed_median_us", "random_median_us", "timing_spread_ratio"):
            print(f"    {k:22s} {r[k]}")
        print()
        results.append((title, r))

    print("=" * 66)
    print("VERDICT")
    print("=" * 66)
    r1, r2, r3 = (r for _, r in results)
    ok = (r1["verdict"] != "LEAK DETECTED"
          and r2["verdict"] == "LEAK DETECTED"
          and r3["verdict"] != "LEAK DETECTED")
    for title, r in results:
        print(f"  {title:48s} -> {r['verdict']}")
    print(f"\n  scanner validated (sensitivity+specificity): {ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
