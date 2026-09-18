# BB84 protocol simulation with eavesdropper and channel noise.
#
# Protocol (Bennett-Brassard 1984):
#   1. Alice generates N random bits + N random bases (Z: |0>,|1>  X: |+>,|->)
#   2. She sends each qubit prepared in the chosen basis
#   3. (Eve, with probability p per qubit, intercepts: measures in a RANDOM
#      basis, resends the collapsed state -> disturbs X-prepared qubits 50%)
#   4. Channel noise flips each qubit with probability q
#   5. Bob measures each qubit in his own random basis
#   6. Sifting: keep positions where Alice's and Bob's bases match
#   7. QBER: fraction of mismatches on a sacrificed sample of the sifted key
#      -> QBER ~ 0: clean channel;  QBER ~ 25%: full intercept-resend Eve
#      (with p intercept rate: QBER ~= p/4 from Eve + q/2 from noise)

import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_bb84(n_bits=2000, eve_rate=0.0, noise_rate=0.0, seed=None):
    """Simulate one BB84 run. Returns dict with sifted key + QBER."""
    rng = np.random.default_rng(seed)

    alice_bits = rng.integers(0, 2, n_bits)
    alice_bases = rng.integers(0, 2, n_bits)   # 0 = Z, 1 = X
    bob_bases = rng.integers(0, 2, n_bits)
    eve_taps = rng.random(n_bits) < eve_rate
    eve_bases = rng.integers(0, 2, n_bits)
    noise = rng.random(n_bits) < noise_rate

    bob_bits = np.empty(n_bits, dtype=int)
    for i in range(n_bits):
        bit, abasis = alice_bits[i], alice_bases[i]

        # Eve intercept-resend: measures in HER random basis.
        if eve_taps[i]:
            if eve_bases[i] == abasis:
                e_bit = bit                      # right basis: no disturbance
            else:
                e_bit = rng.integers(0, 2)       # wrong basis: 50/50 collapse
            sent_basis, sent_bit = eve_bases[i], e_bit
        else:
            sent_basis, sent_bit = abasis, bit

        # Bob measures in his random basis.
        if bob_bases[i] == sent_basis:
            b_bit = sent_bit
        else:
            b_bit = rng.integers(0, 2)           # wrong basis: random outcome

        # Channel noise: bit flip on the transmission.
        if noise[i]:
            b_bit ^= 1
        bob_bits[i] = b_bit

    # Sifting: Bob's basis matched Alice's original basis
    mask = alice_bases == bob_bases
    sifted_a = alice_bits[mask]
    sifted_b = bob_bits[mask]

    errors = int(np.sum(sifted_a != sifted_b))
    qber = errors / len(sifted_a) if len(sifted_a) else float("nan")
    return {
        "sifted_alice": sifted_a,
        "sifted_bob": sifted_b,
        "n_sifted": int(mask.sum()),
        "errors": errors,
        "qber": qber,
    }


def sweep_eve(n_bits=2000, rates=None, trials=30, seed=7):
    """QBER as a function of Eve's intercept rate (noise fixed at 0)."""
    rates = rates if rates is not None else np.linspace(0, 1, 11)
    out = []
    for p in rates:
        qbers = [run_bb84(n_bits, eve_rate=float(p), seed=seed + t)["qber"]
                 for t in range(trials)]
        out.append((float(p), float(np.mean(qbers)), float(np.std(qbers))))
    return out


def sweep_noise(n_bits=2000, rates=None, trials=30, seed=99):
    """QBER as a function of channel noise (Eve absent)."""
    rates = rates if rates is not None else np.linspace(0, 0.2, 9)
    out = []
    for q in rates:
        qbers = [run_bb84(n_bits, noise_rate=float(q), seed=seed + t)["qber"]
                 for t in range(trials)]
        out.append((float(q), float(np.mean(qbers)), float(np.std(qbers))))
    return out


def demo_run():
    print("Single runs (n=2000 sifted from ~4000 sent):")
    for label, kw in [
        ("clean channel            ", dict()),
        ("Eve taps 25% of qubits   ", dict(eve_rate=0.25)),
        ("Eve taps 100%            ", dict(eve_rate=1.00)),
        ("5% channel noise         ", dict(noise_rate=0.05)),
        ("Eve 25% + noise 3%       ", dict(eve_rate=0.25, noise_rate=0.03)),
    ]:
        r = run_bb84(4000, seed=42, **kw)
        print(f"  {label} QBER={r['qber']*100:5.2f}%  "
              f"sifted={r['n_sifted']}  errors={r['errors']}")


if __name__ == "__main__":
    demo_run()
