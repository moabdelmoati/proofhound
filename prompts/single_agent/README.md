# Single-agent prompt (team-authored)

`system.md` holds the system prompt for the single-agent baseline (RQ3): one LLM with the tools
in `src/proofhound/baseline/tools.py`, asked to find and confirm a vulnerability in the commit.

The tools and the dispatch loop (`src/proofhound/baseline/single_agent.py`) are ready; only this
prompt and the provider tool-call wiring are left to write. Keep the prompt versioned (first line
`v1`) so every run logs which version produced it.
