# pqc-scan — CI-friendly CLI over the leak_scanner core.
#
#   python -m pqc_eval.cli <module>.<fn> [options]
#
# Examples:
#   python -m pqc_eval.cli pqc_eval.experiment_01_kyberslash.leaky_loopcount
#   python -m pqc_eval.cli mypkg.crypto.decaps --n-samples 300 --repeats 7
#
# The target function must accept (data: bytes, secret: bytes) and return
# anything. Secrets are random homogeneous bytes (1..255) sized with --key-len.
# The fixed population uses one fixed secret (timing-extreme all-0x01 by
# default, or a random typical one with --fixed-secret random).
# Verdict logic is exactly leakage_report(): p<0.01 AND |d|>0.8 -> LEAK.

import argparse
import importlib
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqc_eval.leak_scanner import scan


def load_target(dotted: str):
    mod_path, _, fn_name = dotted.rpartition(".")
    if not mod_path:
        raise SystemExit(f"target must be module.fn, got: {dotted}")
    mod = importlib.import_module(mod_path)
    fn = getattr(mod, fn_name, None)
    if fn is None or not callable(fn):
        raise SystemExit(f"{mod_path} has no callable {fn_name}")
    return fn


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="pqc-scan",
        description="Timing-leak scan of a python crypto function.")
    ap.add_argument("target",
                    help="dotted path module.fn taking (data: bytes, secret: bytes)")
    ap.add_argument("--key-len", type=int, default=512,
                    help="secret size in bytes (default 512)")
    ap.add_argument("--n-samples", type=int, default=200,
                    help="random-population size (default 200)")
    ap.add_argument("--repeats", type=int, default=5,
                    help="median-of-N repetitions per sample (default 5)")
    ap.add_argument("--fixed-secret", choices=("extreme", "random"),
                    default="extreme",
                    help="fixed population content: all-0x01 extreme or "
                         "one random typical secret (default extreme)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--data", type=str, default="ff",
                    help="hex string passed as the first (public) argument "
                         "(default 'ff')")
    args = ap.parse_args()

    fn = load_target(args.target)
    rng = np.random.default_rng(args.seed)
    data = bytes.fromhex(args.data)
    key_len = args.key_len

    fixed_secret = (bytes([1]) * key_len if args.fixed_secret == "extreme"
                    else bytes(rng.integers(1, 256, key_len, dtype=np.uint8)))

    random_secrets = [bytes(rng.integers(1, 256, key_len, dtype=np.uint8))
                      for _ in range(args.n_samples)]
    pairs = [(data, k) for k in random_secrets]

    def fixed_pair():
        return data, bytes(fixed_secret)   # fresh copy each call

    print(f"pqc-scan: {args.target}")
    print(f"  samples={args.n_samples} repeats={args.repeats} "
          f"key_len={key_len} fixed={args.fixed_secret} seed={args.seed}")
    r = scan(fn, fixed_pair, pairs, repeats=args.repeats)
    for k in ("verdict", "welch_t", "p_value", "cohens_d",
              "fixed_median_us", "random_median_us", "timing_spread_ratio"):
        print(f"  {k:22s} {r[k]}")

    return 1 if r["verdict"] == "LEAK DETECTED" else 0


if __name__ == "__main__":
    sys.exit(main())
