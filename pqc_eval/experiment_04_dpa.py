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
STABILITY_CSV_PATH = os.path.join(HERE, "exp04_dpa_stability.csv")

def _measure_us(fn, secret: bytes, repeats: int) -> float:
    samples = []
    for _ in range(repeats):
        start = time.perf_counter_ns()
        fn(DATA, bytes(secret))
        samples.append((time.perf_counter_ns() - start) / 1_000.0)
    return float(np.median(samples))

def collect(fn, secrets: np.ndarray, repeats: int, seed: int) -> np.ndarray:
    order = np.arange(len(secrets))
    np.random.default_rng(seed).shuffle(order)
    timings = np.empty(len(secrets), dtype=float)
    for index in order:
        timings[index] = _measure_us(fn, secrets[index].tobytes(), repeats)
    return timings

def write_csv(rows: list[dict]) -> None:
    fields = ["target", "trial", "byte", "correlation_r", "p_value", "significant_p_lt_0_01"]
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

def write_stability_csv(summary: dict[str, list[dict]]) -> None:
    fields = ["target", "byte", "times_significant", "n_trials", "mean_abs_r"]
    with open(STABILITY_CSV_PATH, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for name, byte_rows in summary.items():
            for row in byte_rows:
                writer.writerow({"target": name, **row})

def make_plot(mean_abs_r: dict[str, list[float]], n_trials: int) -> None:
    matrix = np.asarray(list(mean_abs_r.values()))
    fig, ax = plt.subplots(figsize=(11, 3.6), constrained_layout=True)
    limit = max(0.05, float(np.max(matrix)))
    image = ax.imshow(matrix, aspect="auto", cmap="Reds", vmin=0, vmax=limit)
    ax.set_yticks(range(len(mean_abs_r)), list(mean_abs_r))
    ax.set_xlabel("Secret byte index")
    ax.set_ylabel("Target")
    ax.set_title(f"Exp 04 - mean |Pearson r| per byte, averaged over {n_trials} independent trials")
    fig.colorbar(image, ax=ax, label="mean |r| across trials")
    fig.savefig(IMAGE_PATH, dpi=180)
    plt.close(fig)

def amplified(fn, rounds=12):
    def wrapped(data, secret):
        result = 0
        for _ in range(rounds):
            result ^= fn(data, secret)
        return result
    return wrapped


def collect_isolated(fn, n_samples: int, n_bytes: int, repeats: int, seed: int) -> dict:
    rng = np.random.default_rng(seed)
    correlations = np.zeros(n_bytes)
    p_values = np.ones(n_bytes)
    for byte_index in range(n_bytes):
        values = rng.integers(1, 256, size=n_samples, dtype=np.uint8)
        secrets = np.full((n_samples, n_bytes), 128, dtype=np.uint8)
        secrets[:, byte_index] = values
        timings = collect(fn, secrets, repeats, seed=seed + byte_index)
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
    # IMPORTANT: a single trial isn't enough to claim "localization" - testing
    # n_bytes independent positions at p<0.01 will flag ~1 of them by chance
    # even under a null of no localization. leaky_loopcount also has no
    # structural reason to prefer one byte position (it sums a bit-length
    # value across all bytes symmetrically). So we run several INDEPENDENT
    # trials per target and require the SAME byte to be flagged repeatedly
    # before calling it "localized" - exactly the stability check the rest
    # of this repo already applies to the main leak claim (audit_validation.py
    # ATTACK 1/2).
    n_samples, n_bytes, repeats, n_trials = 200, 8, 5, 5
    targets = {"vulnerable_loopcount": amplified(leaky_loopcount), "constanttime_lookup": amplified(constanttime_lookup)}
    print("=" * 68)
    print("EXPERIMENT 04 - DPA-style timing correlation by secret byte")
    print("=" * 68)
    print(f"{n_samples} secrets x {repeats} reps (median), {n_bytes}-byte secret, "
          f"{n_trials} independent trials per target\n")

    rows, mean_abs_r, stability_summary = [], {}, {}
    for name, fn in targets.items():
        trial_results = [collect_isolated(fn, n_samples, n_bytes, repeats,
                                          seed=202604 + 1000 * trial)
                         for trial in range(n_trials)]
        peaks = [r["peak_byte"] for r in trial_results]
        print(f"{name:24s} peak byte per trial: {peaks}")
        for trial, result in enumerate(trial_results):
            for byte, (correlation, p_value) in enumerate(
                    zip(result["correlations"], result["p_values"])):
                rows.append({"target": name, "trial": trial, "byte": byte,
                             "correlation_r": correlation, "p_value": p_value,
                             "significant_p_lt_0_01": p_value < 0.01})

        abs_r_by_byte = np.array([[abs(r["correlations"][b]) for r in trial_results]
                                  for b in range(n_bytes)])
        sig_counts = np.array([sum(1 for r in trial_results if r["p_values"][b] < 0.01)
                               for b in range(n_bytes)])
        mean_abs_r[name] = abs_r_by_byte.mean(axis=1).tolist()
        stability_summary[name] = [
            {"byte": b, "times_significant": int(sig_counts[b]), "n_trials": n_trials,
             "mean_abs_r": round(float(abs_r_by_byte[b].mean()), 6)}
            for b in range(n_bytes)]

        most_flagged_byte = int(np.argmax(sig_counts))
        most_flagged_count = int(sig_counts[most_flagged_byte])
        stable = most_flagged_count >= (n_trials // 2 + 1)  # majority of trials
        verdict = (f"STABLE LOCALIZATION at byte {most_flagged_byte} "
                  f"({most_flagged_count}/{n_trials} trials)" if stable else
                  f"NO STABLE LOCALIZATION - peak byte varies across trials "
                  f"(best: byte {most_flagged_byte}, only {most_flagged_count}/{n_trials})")
        print(f"{'':24s} {verdict}\n")

    write_csv(rows)
    write_stability_csv(stability_summary)
    make_plot(mean_abs_r, n_trials)
    print(f"CSV (per-trial):  {os.path.relpath(CSV_PATH, ROOT)}")
    print(f"CSV (stability):  {os.path.relpath(STABILITY_CSV_PATH, ROOT)}")
    print(f"Plot:             {os.path.relpath(IMAGE_PATH, ROOT)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
