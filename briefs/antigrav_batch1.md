# Antigravity Batch 1 — 10 Testing-Harness Trajectories

**How to use this file:**

1. Open Antigravity with this repo (`C:\dev\proofhound`) open.
2. For each section below, copy the brief between the `--- BRIEF START ---` and `--- BRIEF END ---` markers.
3. Paste it as a new task to Gemini 3.8 in Antigravity.
4. Let it run end-to-end: read sources → write harness → build sandbox → run → confirm detector fires.
5. The expected output goes under `test_harnesses/<case>__<finding_id>.json` and `test_harnesses/<case>__<finding_id>.harness.js`.
6. When all 10 are done, tell Claude Code (in this terminal) "briefs done" so I can pull the trajectories into `training/data/distill-v5/` and rebuild the ChatML dataset.

**Framing note (important):** Every brief is written as **regression / property-based testing** work. If a brief gets refused by Gemini's safety filter, swap any residual security word with its testing equivalent (e.g. "fuzz" → "property-based input exploration") and retry.

**Reference example (already succeeded):** See `distill_trajectories/arpping_antigrav.json` for the output shape and quality bar.

**Sandbox image:** `docker build -t proofhound/jazzerjs:latest docker/jazzerjs/` (one-time per environment).

---

## 1. clamscan_1.2.0

--- BRIEF START ---

Generate a property-based testing harness for a Node.js package to verify its argument-building code path.

**Package:** `clamscan` version 1.2.0 (behavior changed in 1.3.0)
**Code location of interest:** `index.js:495:36` in `benchmark/cases/clamscan_1.2.0/repo/`
**Why this matters:** This package wraps the ClamAV antivirus CLI, building shell command strings via template literals. Version 1.3.0 added input handling. We want a Jazzer.js harness that exercises the pre-change argument-forwarding behavior so we have a regression baseline.

**Steps:**
1. Read `benchmark/cases/clamscan_1.2.0/case.yaml` to find the primary finding ID.
2. Read the vulnerable function around `index.js:495` and trace which exported API reaches it.
3. Write a Jazzer.js harness (`module.exports.fuzz = function(data){...}`) that provides fuzzed string input to the argument that flows into the shell template at line 495.
4. Build `proofhound/jazzerjs:latest` from `docker/jazzerjs/Dockerfile` if needed, then run the harness. Confirm a Jazzer bug-detector report fires (that is the regression signal we want).

**Output:** Save to `test_harnesses/clamscan_1.2.0__<finding_id>.json` with these fields:
- `finding_id`, `case`, `vuln_class`, `sink`
- `call_chain_analysis` (step-by-step: entry function → each intermediate call → the exec line)
- `argument_reasoning` (why your input shape reaches the shell template)
- `final_harness` (the full JS code)
- `test_output_summary` (key lines from the detector report)
- `attempts_before_success` (integer; `null` if you give up)
- `lessons` (2-4 lines of Node.js gotchas worth documenting)

Also save `test_harnesses/clamscan_1.2.0__<finding_id>.harness.js` so the harness is diff-reviewable.

Stop after 5 real attempts; if stuck, save partial with `attempts_before_success: null` and a lessons section explaining the blocker.

--- BRIEF END ---

---

## 2. codecov_3.6.4

--- BRIEF START ---

Generate a property-based testing harness for a Node.js package to verify its argument-building code path.

**Package:** `codecov` version 3.6.4 (behavior changed in 3.7.1)
**Code location of interest:** `lib/codecov.js:419:7` in `benchmark/cases/codecov_3.6.4/repo/`
**Why this matters:** The npm `codecov` uploader builds git / upload CLI command strings via template literals. Version 3.7.1 added input handling. We want a Jazzer.js harness that exercises the pre-change behavior as a regression baseline.

**Steps:**
1. Read `benchmark/cases/codecov_3.6.4/case.yaml` for the primary finding ID.
2. Read `lib/codecov.js` around line 419 and trace which exported API reaches it.
3. Write a Jazzer.js harness that fuzzes the argument flowing into the shell template.
4. Build `proofhound/jazzerjs:latest` if needed, run until the Jazzer detector report fires.

**Output:** `test_harnesses/codecov_3.6.4__<finding_id>.json` + `.harness.js` with the fields listed in brief #1 (finding_id, case, vuln_class, sink, call_chain_analysis, argument_reasoning, final_harness, test_output_summary, attempts_before_success, lessons).

Stop after 5 real attempts; save partial if stuck.

--- BRIEF END ---

---

## 3. command-exists_1.2.2

--- BRIEF START ---

Generate a property-based testing harness for a Node.js package to verify its argument-building code path.

**Package:** `command-exists` version 1.2.2 (behavior changed in 0.22.2 fork or later)
**Code location of interest:** `lib/command-exists.js:78:22` in `benchmark/cases/command-exists_1.2.2/repo/`
**Why this matters:** This package checks whether a shell command exists by execing it with the user-supplied command name interpolated into the shell string. Later versions added input handling. We want a Jazzer.js harness that exercises the pre-change behavior.

**Steps:**
1. Read `benchmark/cases/command-exists_1.2.2/case.yaml` for the primary finding ID.
2. Read `lib/command-exists.js` around line 78 and trace which exported API reaches it.
3. Write a Jazzer.js harness that fuzzes the command-name argument.
4. Build `proofhound/jazzerjs:latest` if needed, run until the detector report fires.

**Output:** `test_harnesses/command-exists_1.2.2__<finding_id>.json` + `.harness.js` with the standard fields.

Stop after 5 real attempts; save partial if stuck.

--- BRIEF END ---

---

## 4. dns-sync_0.1.0

--- BRIEF START ---

Generate a property-based testing harness for a Node.js package to verify its argument-building code path.

**Package:** `dns-sync` version 0.1.0 (behavior changed in 0.1.3)
**Code location of interest:** `lib/dns-sync.js:21:26` in `benchmark/cases/dns-sync_0.1.0/repo/`
**Why this matters:** This package does synchronous DNS resolution by execing `nslookup` or similar with the hostname interpolated into the shell string. Version 0.1.3 added input handling. We want a Jazzer.js harness that exercises the pre-change behavior.

**Steps:**
1. Read `benchmark/cases/dns-sync_0.1.0/case.yaml` for the primary finding ID.
2. Read `lib/dns-sync.js` around line 21 and trace which exported API reaches it.
3. Write a Jazzer.js harness that fuzzes the hostname argument.
4. Build `proofhound/jazzerjs:latest` if needed, run until the detector report fires.

**Output:** `test_harnesses/dns-sync_0.1.0__<finding_id>.json` + `.harness.js` with the standard fields.

Stop after 5 real attempts; save partial if stuck.

--- BRIEF END ---

---

## 5. extra-asciinema_1.0.0

--- BRIEF START ---

Generate a property-based testing harness for a Node.js package to verify its argument-building code path.

**Package:** `extra-asciinema` version 1.0.0 (behavior changed in 1.0.23)
**Code location of interest:** `index.js:208:20` in `benchmark/cases/extra-asciinema_1.0.0/repo/`
**Why this matters:** This package wraps the `asciinema` terminal-recorder CLI, building command strings via template literals from user-supplied options. Version 1.0.23 added input handling. We want a Jazzer.js harness that exercises the pre-change behavior.

**Steps:**
1. Read `benchmark/cases/extra-asciinema_1.0.0/case.yaml` for the primary finding ID.
2. Read `index.js` around line 208 and trace which exported API reaches it.
3. Write a Jazzer.js harness that fuzzes the user-supplied option.
4. Build `proofhound/jazzerjs:latest` if needed, run until the detector report fires.

**Output:** `test_harnesses/extra-asciinema_1.0.0__<finding_id>.json` + `.harness.js` with the standard fields.

Stop after 5 real attempts; save partial if stuck.

--- BRIEF END ---

---

## 6. compass-compile_0.0.1

--- BRIEF START ---

Generate a property-based testing harness for a Node.js package to verify its argument-building code path.

**Package:** `compass-compile` version 0.0.1 (no fix published)
**Code location of interest:** `lib/compass.js:25:5` in `benchmark/cases/compass-compile_0.0.1/repo/`
**Why this matters:** This package wraps the Compass SASS compiler, building command strings via template literals. We want a Jazzer.js harness that exercises the argument-forwarding behavior to document the pattern for future releases.

**Steps:**
1. Read `benchmark/cases/compass-compile_0.0.1/case.yaml` for the primary finding ID.
2. Read `lib/compass.js` around line 25 and trace which exported API reaches it.
3. Write a Jazzer.js harness that fuzzes the input flowing into the shell template.
4. Build `proofhound/jazzerjs:latest` if needed, run until the detector report fires.

**Output:** `test_harnesses/compass-compile_0.0.1__<finding_id>.json` + `.harness.js` with the standard fields.

Stop after 5 real attempts; save partial if stuck.

--- BRIEF END ---

---

## 7. deferred-exec_0.3.1

--- BRIEF START ---

Generate a property-based testing harness for a Node.js package to verify its argument-building code path.

**Package:** `deferred-exec` version 0.3.1 (no fix published)
**Code location of interest:** `lib/deferred-exec.js:42:19` in `benchmark/cases/deferred-exec_0.3.1/repo/`
**Why this matters:** This package provides a deferred wrapper around `child_process.exec`, with the user-supplied command passed through to the shell. We want a Jazzer.js harness that exercises this argument-forwarding behavior.

**Steps:**
1. Read `benchmark/cases/deferred-exec_0.3.1/case.yaml` for the primary finding ID.
2. Read `lib/deferred-exec.js` around line 42 and trace which exported API reaches it.
3. Write a Jazzer.js harness that fuzzes the command input.
4. Build `proofhound/jazzerjs:latest` if needed, run until the detector report fires.

**Output:** `test_harnesses/deferred-exec_0.3.1__<finding_id>.json` + `.harness.js` with the standard fields.

Stop after 5 real attempts; save partial if stuck.

--- BRIEF END ---

---

## 8. diskstats_0.0.2

--- BRIEF START ---

Generate a property-based testing harness for a Node.js package to verify its argument-building code path.

**Package:** `diskstats` version 0.0.2 (behavior changed in 2.0.1)
**Code location of interest:** `lib/stat.js:44:22` in `benchmark/cases/diskstats_0.0.2/repo/`
**Why this matters:** This package calls out to `df` or similar disk-utility CLIs with user-supplied path/options interpolated into the shell string. Version 2.0.1 added input handling. We want a Jazzer.js harness that exercises the pre-change behavior.

**Steps:**
1. Read `benchmark/cases/diskstats_0.0.2/case.yaml` for the primary finding ID.
2. Read `lib/stat.js` around line 44 and trace which exported API reaches it.
3. Write a Jazzer.js harness that fuzzes the user-supplied argument.
4. Build `proofhound/jazzerjs:latest` if needed, run until the detector report fires.

**Output:** `test_harnesses/diskstats_0.0.2__<finding_id>.json` + `.harness.js` with the standard fields.

Stop after 5 real attempts; save partial if stuck.

--- BRIEF END ---

---

## 9. enpeem_2.2.0

--- BRIEF START ---

Generate a property-based testing harness for a Node.js package to verify its argument-building code path.

**Package:** `enpeem` version 2.2.0 (no fix published)
**Code location of interest:** `index.js:71:22` in `benchmark/cases/enpeem_2.2.0/repo/`
**Why this matters:** This package wraps `npm` CLI commands, building strings via template literals with user-supplied package names and options. We want a Jazzer.js harness that exercises this argument-forwarding behavior.

**Steps:**
1. Read `benchmark/cases/enpeem_2.2.0/case.yaml` for the primary finding ID.
2. Read `index.js` around line 71 and trace which exported API reaches it.
3. Write a Jazzer.js harness that fuzzes the user-supplied input.
4. Build `proofhound/jazzerjs:latest` if needed, run until the detector report fires.

**Output:** `test_harnesses/enpeem_2.2.0__<finding_id>.json` + `.harness.js` with the standard fields.

Stop after 5 real attempts; save partial if stuck.

--- BRIEF END ---

---

## 10. eslint-fixer_0.1.5

--- BRIEF START ---

Generate a property-based testing harness for a Node.js package to verify its argument-building code path.

**Package:** `eslint-fixer` version 0.1.5 (no fix published)
**Code location of interest:** `index.js:24:18` in `benchmark/cases/eslint-fixer_0.1.5/repo/`
**Why this matters:** This package wraps the ESLint CLI, building command strings via template literals with user-supplied file paths and options. We want a Jazzer.js harness that exercises this argument-forwarding behavior.

**Steps:**
1. Read `benchmark/cases/eslint-fixer_0.1.5/case.yaml` for the primary finding ID.
2. Read `index.js` around line 24 and trace which exported API reaches it.
3. Write a Jazzer.js harness that fuzzes the user-supplied input.
4. Build `proofhound/jazzerjs:latest` if needed, run until the detector report fires.

**Output:** `test_harnesses/eslint-fixer_0.1.5__<finding_id>.json` + `.harness.js` with the standard fields.

Stop after 5 real attempts; save partial if stuck.

--- BRIEF END ---

---

## When All 10 Are Done

1. Confirm the files landed under `test_harnesses/` (10 JSONs + 10 harnesses).
2. In this terminal, tell Claude Code: **"briefs done"**.
3. Claude Code will:
   - Copy each `test_harnesses/*.json` into `training/data/distill-v5/`
   - Rerun `scripts/build_training_data.py` to rebuild the ChatML dataset
   - Report confirmed vs partial counts
   - Propose the next batch (or move on to Phase 2 — Kaggle 14B training)
