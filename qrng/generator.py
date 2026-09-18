# Quantum RNG: each bit = one shot of |0> --H--> |+> measured (50/50).
#
# Implementation: a single 1-qubit circuit executed with shots=N and
# memory=True — every shot is an independent quantum measurement and Aer's
# memory returns the per-shot outcomes in order. This is both faster and
# wider than wide circuits (transpilers cap circuit width; shots don't).

import numpy as np
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator

SIM = AerSimulator()
_CHUNK = 100_000  # shots per run


def quantum_bits(n: int, seed: int | None = None) -> np.ndarray:
    """n independent Hadamard-measurement bits via Aer, in order."""
    out = []
    while len(out) < n:
        shots = min(_CHUNK, n - len(out))
        qc = QuantumCircuit(1, 1)
        qc.h(0)
        qc.measure(0, 0)
        compiled = transpile(qc, SIM, optimization_level=0)
        result = SIM.run(compiled, shots=shots, memory=True,
                         seed_simulator=seed).result()
        mem = result.get_memory()          # list of '0'/'1', ordered
        out.extend(int(b) for b in mem)
        seed = None                        # only fix seed for the first chunk
    return np.array(out[:n], dtype=np.uint8)


def classical_bits(n: int, seed: int | None = None) -> np.ndarray:
    """numpy PCG64 PRNG bits (the 'classical' comparison baseline)."""
    rng = np.random.default_rng(seed)
    return rng.integers(0, 2, n, dtype=np.uint8)


if __name__ == "__main__":
    q = quantum_bits(16, seed=1)
    c = classical_bits(16, seed=1)
    print("quantum bits:  ", "".join(map(str, q)))
    print("classical bits:", "".join(map(str, c)))
