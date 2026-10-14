# Harness Agent prompts (team-authored)

Prompt files for the Harness Agent (`src/proofhound/agents/harness.py`):
- `system.md` — role, output format, constraints.
- `user.md` — the finding, the target function, the template (placeholders filled by the agent).
- `repair.md` — the failed harness, the failed stage, and the error.

First line of each file is the prompt version (e.g. `v1`), logged with every attempt.
