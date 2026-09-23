"""Experiment 04 - DPA-style timing correlation by secret byte."""

from __future__ import annotations
import csv
import os
import sys
import time
import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pqc_eval.leak_scanner import dpa_correlation
from pqc_eval.experiment_01_kyberslash import DATA, constanttime_lookup, leaky_loopcount

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
IMAGE_PATH = os.path.join(ROOT, "images", "exp04_dpa_correlation.png")
CSV_PATH = os.path.join(HERE, "exp04_dpa_results.csv")

def _measure_us(fn, secret: bytes, repeats: int) -> float:
    samples = []
    for _ in range(repeats):
        start = time.perf_counter_ns()
        fn(DATA, bytes(secret))
        samples.append((time.perf_counter_ns() - start) / 1_000.0)
    return float(np.median(samples))

def collect(fn, secrets: np.ndarray, repeats: int) -> np.ndarray:
    order = np.arange(len(secrets))
    np.random.default_rng(202604).shuffle(order)
    timings = np.empty(len(secrets), dtype=float)
    for index in order:
        timings[index] = _measure_us(fn, secrets[index].tobytes(), repeats)
    return timings

def write_csv(rows: list[dict]) -> None:
    fields = ["target", "byte", "correlation_r", "p_value", "significant_p_lt_0_01"]
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

def make_plot(results: dict[str, dict]) -> None:
    matrix = np.asarray([r["correlations"] for r in results.values()])
    fig, ax = plt.subplots(figsize=(11, 3.6), constrained_layout=True)
    limit = max(0.05, float(np.max(np.abs(matrix))))
    image = ax.imshow(matrix, aspect="auto", cmap="coolwarm", vmin=-limit, vmax=limit)
    ax.set_yticks(range(len(results)), list(results))
    ax.set_xlabel("Secret byte index")
    ax.set_ylabel("Target")
    ax.set_title("Exp 04 - timing / secret-byte Pearson correlation")
    fig.colorbar(image, ax=ax, label="Pearson r")
    fig.savefig(IMAGE_PATH, dpi=180)
    plt.close(fig)

def amplified(fn, rounds=12):
    def wrapped(data, secret):
        result = 0
        for _ in range(rounds):
            result ^= fn(data, secret)
        return result
    return wrapped


def collect_isolated(fn, n_samples: int, n_bytes: int, repeats: int) -> dict:
    rng = np.random.default_rng(202604)
    correlations = np.zeros(n_bytes)
    p_values = np.ones(n_bytes)
    for byte_index in range(n_bytes):
        values = rng.integers(1, 256, size=n_samples, dtype=np.uint8)
        secrets = np.full((n_samples, n_bytes), 128, dtype=np.uint8)
        secrets[:, byte_index] = values
        timings = collect(fn, secrets, repeats)
        result = dpa_correlation(timings, secrets[:, [byte_index]])
        correlations[byte_index] = result["correlations"][0]
        p_values[byte_index] = result["p_values"][0]
    peak = int(np.argmax(np.abs(correlations)))
    return {"correlations": [round(float(v), 6) for v in correlations],
            "p_values": [float(v) for v in p_values], "peak_byte": peak,
            "peak_r": float(correlations[peak]), "peak_abs_r": float(abs(correlations[peak])),
            "significant_bytes": [int(i) for i in np.flatnonzero(p_values < 0.01)],
            "n_samples": n_samples, "n_bytes": n_bytes}

def main() -> int:
    n_samples, n_bytes, repeats = 200, 8, 5
    targets = {"vulnerable_loopcount": amplified(leaky_loopcount), "constanttime_lookup": amplified(constanttime_lookup)}
    print("=" * 68)
    print("EXPERIMENT 04 - DPA-style timing correlation by secret byte")
    print("=" * 68)
    print(f"{n_samples} secrets x {repeats} reps (median), {n_bytes}-byte secret\n")
    results, rows = {}, []
    for name, fn in targets.items():
        result = collect_isolated(fn, n_samples, n_bytes, repeats)
        results[name] = result
        peak = result["peak_byte"]
        print(f"{name:24s} peak byte={peak:2d} r={result['peak_r']:+.4f} "
              f"p={result['p_values'][peak]:.3e} significant bytes={len(result['significant_bytes'])}")
        for byte, (correlation, p_value) in enumerate(zip(result["correlations"], result["p_values"])):
            rows.append({"target": name, "byte": byte, "correlation_r": correlation,
                         "p_value": p_value, "significant_p_lt_0_01": p_value < 0.01})
    write_csv(rows)
    make_plot(results)
    print(f"\nCSV:  {os.path.relpath(CSV_PATH, ROOT)}")
    print(f"Plot: {os.path.relpath(IMAGE_PATH, ROOT)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
