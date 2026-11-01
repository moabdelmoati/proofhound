"""The execution check every harness must pass: syntax, a short fuzz probe, coverage of the target.

Shared by the HarnessAgent (multi-agent) and the single agent's tools, so both architectures judge
a harness by exactly the same standard. A harness has `reached` its target only when coverage
records the target function executing.
"""

import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from proofhound.core.adapters.base import LanguageAdapter
from proofhound.core.fuzzing.sandbox import OUT, DockerSandbox
from proofhound.core.fuzzing.seeds import seed_corpus
from proofhound.core.models import ChangedFunction, kind_matches_class

FAILURE_LIMIT = 2000  # characters of failure text handed back to the model

# Lines in a probe log that never explain why a harness failed: libFuzzer/Jazzer status lines,
# Node's circular-dependency warning, and stack frames inside Jazzer or Node itself.
_NOISE = re.compile(
    r"^(INFO: |#\d+\s|MS: |Done \d+ runs|Dictionary: |\(node:\d+\) Warning: Accessing non-existent"
    r"|\(Use `node --trace-warnings"
    r"|\s+at .*(/opt/jazzer/|node:internal|node_modules/(@jazzer\.js|source-map-support|append-transform)))"
)


def summarize_failure(output: str, limit: int = FAILURE_LIMIT) -> str:
    """The part of a check's output that explains the failure, without status noise and cut to
    `limit` characters (head and tail kept), so a long log cannot crowd the source out of a
    repair prompt. The full log stays on disk."""
    lines = [line for line in output.splitlines() if not _NOISE.match(line)]
    text = "\n".join(lines).strip()
    if len(text) <= limit:
        return text
    head = limit * 3 // 4
    tail = limit - head
    return f"{text[:head]}\n... {len(text) - limit} characters omitted ...\n{text[-tail:]}"


@dataclass
class HarnessCheck:
    syntax_ok: bool = False
    loaded: bool = False
    reached: bool = False
    confirmed: bool = False
    failed_stage: str | None = None  # syntax | probe | reach | sandbox
    error: str = ""
    sandbox_error: Exception | None = None  # infrastructure failure; callers re-raise it

    @property
    def passed(self) -> bool:
        return self.syntax_ok and self.loaded and self.reached


def check_harness(
    sandbox: DockerSandbox, adapter: LanguageAdapter, function: ChangedFunction,
    target: Path, out: Path, probe_time_s: int,
    vuln_class: str | None = None,
    class_seeds: bool = True,
    fuzz_inline: bool = False,
    fuzz_time_s: int | None = None,
) -> HarnessCheck:
    """Check `out/harness.js` against `function` in `target`. Never raises: a sandbox failure is
    returned in `sandbox_error` with the stages that completed before it."""
    check = HarnessCheck()
    # Jazzer.js requires the corpus directory to exist before the probe run.
    corpus = out / "corpus"
    corpus.mkdir(parents=True, exist_ok=True)
    if class_seeds and vuln_class:
        seed_corpus(corpus, vuln_class)
    try:
        syntax = sandbox.run(["node", "--check", f"{OUT}/harness.js"], target, out, timeout_s=30)
        check.syntax_ok = syntax.exit_code == 0 and not syntax.timed_out
        if not check.syntax_ok:
            check.failed_stage = "syntax"
            check.error = (
                summarize_failure(syntax.output) or f"node --check exited with {syntax.exit_code}"
            )
            return check

        probe = sandbox.run(
            adapter.fuzz_command(probe_time_s), target, out, timeout_s=probe_time_s + 45,
        )
        (out / "harness-probe.log").write_text(probe.output, encoding="utf-8")
        reports = adapter.parse_reports(probe.output)
        if vuln_class and any(r.is_vulnerability and kind_matches_class(r.kind, vuln_class) for r in reports):
            check.confirmed = True
        check.loaded = (
            not probe.timed_out
            and not any(r.kind == "Uncaught Exception" for r in reports)
            and (probe.exit_code == 0 or any(r.is_vulnerability for r in reports))
        )
        if not check.loaded:
            check.failed_stage = "probe"
            check.error = summarize_failure(probe.output) or (
                "The harness probe timed out." if probe.timed_out
                else f"The harness probe exited with status {probe.exit_code}."
            )
            return check

        # Never accept a coverage report left by an earlier attempt.
        shutil.rmtree(out / "coverage", ignore_errors=True)
        coverage = sandbox.run(adapter.coverage_command("corpus"), target, out, timeout_s=60)
        (out / "coverage.log").write_text(coverage.output, encoding="utf-8")
        hits = adapter.function_hits(out, function)
        check.reached = hits is not None and hits > 0
        if not check.reached:
            check.failed_stage = "reach"
            check.error = (
                "Coverage did not record execution of the target function." if hits is not None
                else "No Jazzer.js coverage report was produced; check that the target loads."
            )
        elif fuzz_inline and not check.confirmed:
            fuzz_s = fuzz_time_s or probe_time_s
            fuzz_run = sandbox.run(
                adapter.fuzz_command(fuzz_s), target, out, timeout_s=fuzz_s + 45,
            )
            (out / "fuzz-inline.log").write_text(fuzz_run.output, encoding="utf-8")
            fuzz_reports = adapter.parse_reports(fuzz_run.output)
            if vuln_class and any(r.is_vulnerability and kind_matches_class(r.kind, vuln_class) for r in fuzz_reports):
                check.confirmed = True
    except Exception as e:
        check.failed_stage = "sandbox"
        check.error = f"{type(e).__name__}: {e}"
        check.sandbox_error = e
    return check
