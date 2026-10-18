# Single-agent prompt

`system.md` is the single agent's system prompt. Its first line is the prompt version (logged in
every run's `single_agent.json`); bump it whenever the wording changes. `{tools}` and
`{harness_template}` are filled in from `tools.py` and the language adapter, so the prompt always
matches what the tools accept.
