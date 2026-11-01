# ProofHound for VS Code

Prove vulnerabilities instead of guessing — [ProofHound](https://github.com/moabdelmoati/proofhound)
analysis and fuzzing for JavaScript/TypeScript, surfaced as diagnostics in your editor.

## Requirements

The extension drives the ProofHound CLI. Install it first:

```bash
pip install proofhound
```

Make sure `proofhound` is on your `PATH`, or set `proofhound.executable` to its full path.
The full scan (`Scan & Prove`) additionally needs Docker and a model endpoint
(`MODEL_ENDPOINT`); the `Analyze` command is SAST-only and needs neither.

## Commands

Open the Command Palette (`Ctrl/Cmd+Shift+P`):

- **ProofHound: Analyze Changed Functions (SAST)** — fast static pass over the functions
  changed by the current commit. No Docker/GPU. Findings appear in the Problems panel and
  as inline markers.
- **ProofHound: Scan & Prove (full pipeline)** — SAST → LLM harness generation → fuzzing.
  Confirmed findings are proven exploitable.
- **ProofHound: Clear Findings** — clear the diagnostics.

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `proofhound.executable` | `proofhound` | Path to the ProofHound CLI. |
| `proofhound.config` | `configs/default.yaml` | Config file, relative to the workspace root. |
| `proofhound.commit` | `HEAD` | Git commit to analyze against its parent. |

## How it works

Each command runs the CLI with `--sarif`, then loads the resulting SARIF 2.1.0 report into a
diagnostic collection. Confirmed findings (from the full pipeline) show as errors; unproven SAST
findings show as warnings or information.
