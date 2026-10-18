# ProofHound — Literature Review (Term 1, T1-A deliverable)

Related work on LLM-based fuzzing, fuzz-driver generation, and automated vulnerability
discovery/repair, and where ProofHound differs. This is the T1-A "related-work notes" deliverable.

---

## 1. LLM-powered vulnerability discovery and patching

### FuzzingBrain (Sheng et al., arXiv:2509.07225, 2025)
An LLM-powered Cyber Reasoning System built for DARPA's AI Cyber Challenge (AIxCC), where it
placed 4th in the final. Core services: a central coordinator that splits and assigns tasks,
a static-analysis service for function metadata and call paths, worker services that generate
exploits and patches with fuzzing + LLM strategies, and a submission service. In the competition
it found 28 vulnerabilities (6 zero-days) in open-source **C and Java** projects and patched 14.
Code: `github.com/o2lab/afc-crs-all-you-need-is-a-fuzzing-brain`.
- **Gap for us:** targets C/Java competition harnesses, not JS/npm; no SAST-guided harness
  generation; no explicit SAST+fuzzing fusion score.

### FuzzingBrain V2 (Sheng et al., arXiv:2605.21779, 2026)
A **multi-agent** successor. Identifies three gaps it addresses: high false-positive rates in
LLM-generated reports, loss of context in function-level vs. line-level analysis, and complex
cross-function trigger conditions. Key ideas: a control-flow-based "Suspicious Point" abstraction
for localization, logic-driven hierarchical function analysis with dual-layer fuzzing, and
MCP-based static/dynamic analysis tools. Reports 36/40 (90%) on the AIxCC C/C++ benchmark and
tens of zero-days in OSS-Fuzz projects (numbers vary by version).
- **Why it matters to us:** it is the closest multi-agent system and the main novelty risk. Our
  differentiators stand: (a) **JS/TypeScript + npm**, not C/C++; (b) SAST findings *guide* harness
  generation; (c) an explicit, auditable SAST+fuzzing **fusion score**; (d) a controlled
  **single-agent vs. multi-agent** comparison on the same infrastructure (RQ3), which V2 does not
  report. We must read V2 in full and position against it precisely.

## 2. LLM-based fuzz-driver generation

### Zhang et al., "How Effective Are They?" (ISSTA 2024, arXiv:2307.12469)
The largest study of LLM-based fuzz-driver generation: a benchmark of 86 driver-generation
questions from 30 widely-used **C** projects, six prompting strategies across five LLMs and five
temperatures — hundreds of thousands of generated drivers and multiple CPU-years of fuzzing.
Findings most relevant to us:
- LLMs **struggle with APIs that have intricate specifics**.
- Three prompt choices help: **repeat queries**, **querying with examples**, and an **iterative
  (repair) querying process**.
- LLM drivers can reach fuzzing results comparable to industry drivers; insights fed into
  **OSS-Fuzz-Gen**.
- **Use for us:** direct evidence for our design — the SAST source/sink hint is extra context for
  the "intricate API" problem (RQ1), and our repair loop is the "iterative querying" they found
  effective. Their benchmark is C; ours is JS/npm.

## 3. LLM-generated inputs/programs (adjacent, not driver-for-SAST)

### Fuzz4All (Xia et al., ICSE 2024, arXiv:2308.04748)
The first *universal* fuzzer: an LLM as input generator/mutator with autoprompting and an
LLM-powered fuzzing loop, across six input languages (C, C++, Go, SMT2, Java, Python). Found 98
bugs (64 confirmed new) in GCC, Clang, Z3, CVC5, OpenJDK, Qiskit.
- **Difference:** fuzzes language/compiler front-ends with LLM-generated *inputs*; it does not
  confirm SAST findings in application code per commit.

### TitanFuzz (Deng et al., ISSTA 2023, arXiv:2212.14834)
Uses generative + infilling LLMs to produce valid programs for fuzzing **deep-learning libraries**
(TensorFlow, PyTorch), with a fitness function favouring deep data dependencies and unique APIs.
~30–50% higher coverage than prior DL fuzzers; ~65 bugs.
- **Difference:** targets DL-library APIs, a different setting from per-commit application security.

## 4. Benchmark

### SecBench.js (Bhuiyan et al., ICSE 2023)
The first broad collection of **server-side JavaScript / npm** vulnerabilities paired with working
exploits and an oracle, plus fixed versions (so detection *and* mitigation can be measured). 600
vulnerabilities from Snyk, GitHub Advisories, and Huntr.dev across five classes — code injection,
command injection, path traversal, prototype pollution, ReDoS. Dynamic analysis of sink calls
(e.g. `exec()`) gives ground-truth sink locations; the work also found 20 zero-days.
- **Use for us:** our primary benchmark. We turn each case into a two-commit repo (benign →
  vulnerable) and use its sink location + exploit as ground truth. Caveat we must document: the
  metadata is noisy (some `fixedVersion`/`fixCommit` values are wrong), so our builder falls back
  to an "introduce" mode.

## 5. Where ProofHound sits

| Dimension | Prior work | ProofHound |
|---|---|---|
| Target ecosystem | C/C++, Java, DL libs, compilers | **JavaScript/TypeScript + npm** (then Python) |
| What drives the harness | task spec / API docs / autoprompt | **SAST source→sink finding** (RQ1) |
| False-positive handling | reported as a problem (V2) | **explicit SAST+fuzzing fusion score** (RQ2) |
| Architecture study | single or multi, not compared | **controlled single vs. multi-agent** (RQ3) |
| Repair | patches (FuzzingBrain) | **execution-validated** patch (re-fuzz + tests) |
| Models | large API models | **small fine-tuned models in a cascade** under a large model (RQ6) |

Our claims are deliberately narrow and testable: JS/TS focus where few LLM-fuzzing systems exist;
joint static+dynamic evidence in one score; execution-validated repair; and a rigorous
single-vs-multi-agent and ablation study. We do **not** claim to beat systems built for C/Java
competitions, which target a different setting.

## 6. Open items

- Read FuzzingBrain V2 in full and write a point-by-point novelty delta.
- Confirm SecBench.js per-class counts from the original paper (the five-class breakdown above is
  from a secondary source).
- Decide whether to cite a second SAST baseline (CodeQL) for RQ2.

## References

- Sheng et al., *All You Need Is A Fuzzing Brain*, arXiv:2509.07225, 2025.
- Sheng et al., *FuzzingBrain V2*, arXiv:2605.21779, 2026.
- Zhang et al., *How Effective Are They? Exploring LLM-Based Fuzz Driver Generation*, ISSTA 2024,
  arXiv:2307.12469, doi:10.1145/3650212.3680355.
- Xia et al., *Fuzz4All: Universal Fuzzing with Large Language Models*, ICSE 2024, arXiv:2308.04748.
- Deng et al., *Large Language Models Are Zero-Shot Fuzzers: Fuzzing Deep-Learning Libraries*,
  ISSTA 2023, arXiv:2212.14834.
- Bhuiyan et al., *SecBench.js: An Executable Security Benchmark Suite for Server-Side JavaScript*,
  ICSE 2023.
