"""Fuses the static (SAST) and dynamic (fuzzing) signals into one confidence score.

This is the Term 1 / early Term 2 core of RQ2: instead of trusting SAST alone, a finding's
confidence is raised when fuzzing reproduces a matching crash and lowered when fuzzing ran but
found nothing. The score is a transparent, rule-based function (no LLM): the paper can report
exactly how each signal moves it. The LLM-based crash classification, PoV script, and CVSS
estimate are added later and only refine the `cvss`/`pov_path` fields, not this score.
"""

from dataclasses import dataclass

from proofhound.models import Crash, FindingStatus, Severity

# Prior confidence from SAST severity alone (a candidate, before any execution evidence).
_SAST_PRIOR = {
    Severity.CRITICAL: 0.55,
    Severity.HIGH: 0.45,
    Severity.MEDIUM: 0.30,
    Severity.LOW: 0.20,
}
CONFIRMED_FLOOR = 0.90  # a reproduced, class-matching crash is near-certain


@dataclass
class Fusion:
    confidence: float
    rationale: str


def _class_matches(vuln_class: str | None, crash: Crash) -> bool:
    """Whether a crash's bug-detector kind matches the finding's vulnerability class."""
    if not vuln_class:
        return True
    kind = crash.kind.lower().replace(" ", "-")
    return vuln_class.lower() in kind or kind in vuln_class.lower()


def fuse(
    severity: Severity,
    vuln_class: str | None,
    status: FindingStatus,
    crashes: list[Crash],
    fuzz_time_s: float,
) -> Fusion:
    """Combine SAST severity and the fuzzing outcome into a confidence in [0, 1]."""
    prior = _SAST_PRIOR.get(severity, 0.30)

    if status == FindingStatus.CONFIRMED and crashes:
        crash = crashes[0]
        if _class_matches(vuln_class, crash):
            score = max(CONFIRMED_FLOOR, prior)
            return Fusion(score, f"fuzzing reproduced {crash.kind} at {crash.sink_location} "
                                 f"({crash.reproduced}x); class matches SAST")
        # Crash of a different class than SAST flagged: real bug, weaker link to this finding.
        return Fusion(0.70, f"fuzzing reproduced {crash.kind}, but SAST flagged {vuln_class}")

    if status == FindingStatus.NOT_CONFIRMED:
        # Fuzzing ran and found nothing: lower the prior, more so the longer it ran clean.
        penalty = 0.5 if fuzz_time_s >= 25 else 0.3
        return Fusion(round(prior * (1 - penalty), 2),
                      f"fuzzed {fuzz_time_s:.0f}s with no matching crash")

    if status == FindingStatus.HARNESS_FAILED:
        # No dynamic evidence either way: report the SAST prior unchanged.
        return Fusion(prior, "no working harness; SAST-only confidence")

    return Fusion(prior, f"no fusion for status {status.value}")
