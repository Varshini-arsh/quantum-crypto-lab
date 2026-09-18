# pqc-eval — Timing-Leak Scanner for Post-Quantum Crypto

> **Problem we're solving:** Post-quantum encryption (ML-KEM/Kyber, FIPS 203) is
> unbreakable by quantum computers — but its *implementations* can leak secret
> keys through execution timing, and there is no accessible open-source tool to
> detect these leaks. Security labs do this with bespoke scripts and $10k
> equipment. This project builds the missing harness.

## What's here

```
pqc_eval/
├── leak_scanner.py             # TVLA-style statistical timing-leak detector
│                                 (Welch t-test + Cohen's d + spread ratio,
│                                  interleaved sampling vs thermal drift)
├── experiment_01_kyberslash.py # Leak reproduction w/ positive+negative controls
├── experiment_02_real_mlkem.py # Scan of REAL kyber_py ML-KEM-768 decaps
└── make_plots.py               # Publication-style visual proof (images/)
```

## Visual proof

| Vulnerable (5.5× timing gap) | Constant-time (clean) | Real ML-KEM-768 |
|---|---|---|
| ![leak](images/exp01_vulnerable_leak.png) | ![clean](images/exp01_constanttime_clean.png) | ![mlkem](images/exp02_real_mlkem.png) |

## Validated results (Windows 11, CPython 3.12, laptop CPU)

| Implementation | Verdict | t | p | Cohen's d |
|---|---|---|---|---|
| Secret-dependent division (KyberSlash pattern) | NO LEAK* | 1.49 | 0.14 | −0.15 |
| **Secret-dependent loop count** (RSA/Kyber reduction family) | **LEAK DETECTED** | −86.3 | 1.6e−168 | 8.65 |
| Constant-time table lookup (patch style) | NO LEAK | 0.17 | 0.87 | −0.02 |

\* Instructive negative result: CPython integer division timing depends on
operand *digit count*, not value — the C-level bug is masked by the interpreter.
**But control-flow leaks (loop counts, conditional reductions) survive in
full force: 5.5× timing difference between fixed and random secrets.**

## Method (why you can trust the verdicts)

- **Positive control**: known-vulnerable code MUST flag (sensitivity)
- **Negative control**: constant-time code MUST NOT flag (specificity)
- **Interleaved A/B sampling** — thermal drift hits both populations equally
- **Homogeneous secret distributions** in fixed and random populations
- Fresh objects per call; median-of-5 per sample; Welch's t-test p<0.01 **and**
  |d|>0.8 required to avoid false alarms

## Experiment 02 — real implementation scan (kyber_py ML-KEM-768)

Pointing the validated scanner at production reference code — ML-KEM-768
decapsulation (the operation an attacker would target):

| Target | Verdict | t | p | Cohen's d |
|---|---|---|---|---|
| `ML_KEM_768.decaps`, fixed-vs-random ciphertexts | **NO LEAK** (Python-timing level) | 0.20 | 0.84 | −0.02 |

The pure-Python reference shows no fixed-vs-random separation at this
resolution. Measurement lesson: individual raw timings span 4×+ from GC pauses —
which is exactly why medians + interleaving + hypothesis tests are required
before calling anything.

## Roadmap

- [x] Statistical core + controls (experiment 01)
- [x] Scan real implementation — kyber_py ML-KEM-768 (experiment 02)
- [ ] Scan liboqs / C-backed bindings (where KyberSlash-class bugs live)
- [ ] DPA-style correlation plots per secret byte
- [ ] DPA-style correlation plots per secret byte
- [ ] BB84 QKD simulation module (hackathon deliverable)
- [ ] QRNG + entropy certification module (hackathon deliverable)
- [ ] CI-friendly CLI: `pqc-scan <module>.<fn> --inputs ...`

## Run it

```bash
pip install numpy scipy
python pqc_eval/experiment_01_kyberslash.py
```
