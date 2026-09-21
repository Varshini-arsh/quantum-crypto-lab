# PROJECT STATUS — pqc-eval (quantum-crypto-lab)

Last updated: 2026-09-18 · Repo: https://github.com/Varshini-arsh/quantum-crypto-lab

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

## Is it DOABLE? — yes, with known limits

**Already done (Day 1):** validated scanner core + 2 experiments + plots, pushed
to GitHub. The hard design decisions are behind us.

**Remaining work, all CPU-only, no datasets, no credentials:**

| Step | Effort | Risk |
|---|---|---|
| Exp 03: scan liboqs C-backed bindings | ~half day | LOW — worst case we publish a clean-bill scan |
| Exp 04: per-byte DPA correlation plots | ~half day | LOW |
| bb84/ module (QKD sim + eavesdropper + QBER plots) | 1 day | NONE — standard, well-understood |
| qrng/ module (Hadamard QRNG + entropy tests) | half day | NONE |
| CLI packaging (`pqc-scan`) + more impl scans | 1 day | LOW |
| Report/writeup (1-2 pages) | half day | NONE |

**Total remaining: ~4-5 working days part-time.** Nothing blocked, nothing
needs hardware we don't have, every step produces a LinkedIn post.

**Honest limits (we state these, not hide them):**
- Laptop timing resolution catches macro-level leaks (µs-scale), not nanosecond
  cache-timing leaks — those need the C-level scans in Exp 03+ or hardware.
- A "NO LEAK" verdict is evidence, not proof (we report statistics, not
  guarantees).
- Pure-Python targets say more about Python than crypto; the C-backed scans
  (Exp 03) are where claims get serious.

## Verdict

STRONG (real gap, real results already, verifiable method) and DOABLE (rest is
well-scoped CPU work). Continue as planned: Exp 03 -> Exp 04 -> bb84 -> qrng ->
CLI -> report.
