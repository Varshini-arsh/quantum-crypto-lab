# BB84 visual proof: QBER vs eavesdropping rate + QBER vs channel noise.

import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bb84.simulator import sweep_eve, sweep_noise

IMG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "images")
os.makedirs(IMG, exist_ok=True)


def main():
    eve = sweep_eve(trials=40)
    noise = sweep_noise(trials=40)

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2), dpi=150)

    # --- QBER vs Eve intercept rate (theory: p/4)
    ax = axes[0]
    p, m, s = zip(*eve)
    ax.errorbar(np.array(p) * 100, np.array(m) * 100, yerr=np.array(s) * 100,
                fmt="o-", color="#8e44ad", capsize=3, label="simulation")
    ax.plot(np.array(p) * 100, np.array(p) / 4 * 100, "--", color="#333",
            lw=1, label="theory (p/4)")
    ax.axhline(11, color="#e74c3c", ls=":", lw=1.5)
    ax.text(2, 12.2, "11% security threshold (abort)", color="#e74c3c",
            fontsize=8)
    ax.set_xlabel("Eve intercept rate (%)")
    ax.set_ylabel("QBER (%)")
    ax.set_title("Detecting the eavesdropper", loc="left", fontweight="bold")
    ax.legend(fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(alpha=0.25)

    # --- QBER vs channel noise (theory: ~q on sifted key)
    ax = axes[1]
    q, m, s = zip(*noise)
    ax.errorbar(np.array(q) * 100, np.array(m) * 100, yerr=np.array(s) * 100,
                fmt="s-", color="#2980b9", capsize=3, label="simulation")
    ax.plot(np.array(q) * 100, np.array(q) * 100, "--", color="#333", lw=1,
            label="theory (q)")
    ax.axhline(11, color="#e74c3c", ls=":", lw=1.5)
    ax.set_xlabel("channel bit-flip noise (%)")
    ax.set_ylabel("QBER (%)")
    ax.set_title("Noise looks like Eve (and that's the point)", loc="left",
                 fontweight="bold")
    ax.legend(fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(alpha=0.25)

    fig.suptitle("BB84 — simulation vs theory (4000 qubits/run, 40 trials)",
                 fontsize=11, y=1.02)
    fig.tight_layout()
    out = os.path.join(IMG, "bb84_qber_sweeps.png")
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print("wrote", out)


if __name__ == "__main__":
    main()
