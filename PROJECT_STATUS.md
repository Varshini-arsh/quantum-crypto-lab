# PROJECT STATUS — pqc-eval (quantum-crypto-lab)

Last updated: 2026-09-23 · Repo: https://github.com/Varshini-arsh/quantum-crypto-lab

## Is this project STRONG? — honest assessment

**Yes, strong — with clear reasons:**

1. **Real problem, real attacks.** KyberSlash (Dec 2023) proved timing leaks in
   ML-KEM implementations are a live threat class; Keysight (Nov 2025) showed
   hardware side-channel attacks on Kyber/Dilithium still work. Not a toy topic.
2. **Genuine gap.** Big implementations got patched; there is NO accessible
   open-source harness to test PQC implementations for timing leaks. Labs do it
   ad-hoc with expensive gear. We build the missing tool.
3. **Already producing original results.** Experiment 01 found that CPython
   masks the C-style KyberSlash division leak (digit-count-driven timing) while
   control-flow leaks explode (5.5x gap, d=8.65). That is a real, shareable
   insight — not a tutorial copy.
4. **Scientific credibility.** Positive + negative controls, interleaved
   sampling, homogeneous populations, effect-size thresholds. Judges/recruiters
   can verify every claim by running one script.
5. **Multipurpose.** Satisfies the Trinexis hackathon deliverable ("evaluate
   post-quantum security models"), feeds a LinkedIn daily series, and doubles as
   an internship-portfolio artifact.

## Is it DOABLE? — DONE (final status, 2026-09-23)

**All planned work is complete.** Final scoreboard:

| Step | Status |
|---|---|
| Exp 01: validated scanner + controls + plots | ✅ DONE (Day 1) |
| Exp 02: real kyber_py ML-KEM-768 scan | ✅ DONE |
| Exp 03: C-backed pqcrypto scan + round-robin drift fix | ✅ DONE |
| Exp 04: per-byte DPA correlation (5-trial stability check; not localized to one byte, self-audit corrected) | ✅ DONE |
| Exp 05: liboqs native scan (built oqs.dll, CLEAN) | ✅ DONE |
| bb84/ (QKD sim, QBER matches theory) | ✅ DONE |
| qrng/ (Hadamard QRNG + entropy battery) | ✅ DONE |
| CLI (`python -m pqc_eval.cli`) | ✅ DONE |
| 15 automated pytest suite | ✅ DONE (15/15 pass) |
| Report/writeup (1-2 pages) | ⬜ optional — README covers the results |

**Honest limits (we state these, not hide them):**
- Laptop timing resolution catches macro-level leaks (µs-scale), not nanosecond
  cache-timing leaks — those need the C-level scans in Exp 03+ or hardware.
- A "NO LEAK" verdict is evidence, not proof (we report statistics, not
  guarantees).
- Pure-Python targets say more about Python than crypto; the C-backed scans
  (Exp 03) are where claims get serious.

## Verdict

STRONG and COMPLETE. All experiments produced verifiable results; the only open
item is the optional nanosecond C-level harness (rdtsc) listed in the README
roadmap — a stretch goal beyond the original scope.
