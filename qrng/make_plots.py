# QRNG visual proof: cumulative +/-1 walk per source.
# A fair source wanders around zero; a biased source drifts visibly.

import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from qrng.generator import classical_bits, quantum_bits

IMG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "images")


def main():
    n = 20_000
    sources = [
        ("QUANTUM (Aer Hadamard)", quantum_bits(n), "#8e44ad"),
        ("CLASSICAL (numpy PCG64)", classical_bits(n, seed=123), "#2980b9"),
        ("BIASED 60/40 (what entropy tests catch)",
         (np.random.default_rng(5).random(n) < 0.6).astype(np.uint8), "#e74c3c"),
    ]

    fig, ax = plt.subplots(figsize=(10, 4.5), dpi=150)
    for name, bits, color in sources:
        walk = np.cumsum(2 * bits.astype(int) - 1)
        ax.plot(walk, lw=1.2, color=color, label=f"{name}  (end {walk[-1]:+d})")

    ax.axhline(0, color="#333", lw=0.8)
    ax.set_xlabel("bit index")
    ax.set_ylabel("cumulative sum (+1 for 1, -1 for 0)")
    ax.set_title("Quantum vs classical vs biased randomness — the drift test",
                 loc="left", fontweight="bold")
    ax.legend(fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(alpha=0.2)
    fig.tight_layout()
    out = os.path.join(IMG, "qrng_walks.png")
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print("wrote", out)


if __name__ == "__main__":
    main()
