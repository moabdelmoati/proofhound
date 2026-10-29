# Antigravity / Gemini task — property-based regression tests for regex performance & object-merge behavior

Paste everything between `--- PROMPT START ---` and `--- PROMPT END ---` into Gemini (Antigravity) with
the `C:\dev\proofhound` repo open. It writes 16 JSON files. Tell Claude Code "briefs done" when finished.

> Note: this is ordinary library-testing work (performance and correctness properties). If a phrasing
> trips a content filter, rephrase in plain testing terms and continue — there is nothing sensitive here.

--- PROMPT START ---

You are writing **property-based regression tests** for npm libraries, to capture two well-known
*behaviors* so a model can learn to reproduce them. Each test is a **Jazzer.js** property test
(`module.exports.fuzz`). The goal is not just to *call* the function of interest, but to make the test
runner's **built-in check actually trigger** — reaching the line is easy; making the property fail is
the whole point.

## The two behaviors and how to make the runner's check fire

**A. Super-linear regex matching (slow-input property).** Some of these libraries contain a regular
expression whose matching time grows super-linearly on certain strings. To make the Jazzer runner's
**per-input timeout** fire:
- Build a long, highly repetitive string with a single non-matching break at the end, e.g.
  `"a".repeat(5000) + "!"` — adapt the repeated character and shape to the specific regex at the target
  line so a single `.test()`/`.match()`/`.replace()` call takes several seconds.
- Pass that string **directly** into the parameter that flows to the regex. Call the exported function
  that runs the regex **as directly as the library's public API allows**.
- Do **not** stub `child_process`/`exec` or other internals to feed the string in — a mocked command
  path rarely drives the regex. Prefer the shortest direct call path. One match must take seconds, which
  the runner reports as a timeout.

**B. Deep-merge writing to a shared prototype (shared-state property).** Some of these libraries have a
recursive merge/clone/set that, given an **object** with a specially-named key, writes onto the shared
`Object.prototype` instead of the target. To make the runner's shared-prototype check fire:
- Pass a real **object** (not a string) whose key is `__proto__` or a `constructor` → `prototype` path,
  e.g. `JSON.parse('{"__proto__":{"touched":true}}')`, into the merge/set/clone function of interest.
- After the call, a brand-new `{}` must show the added property (`({}).touched === true`) — that is what
  the runner detects. Passing the string `"__proto__"` does nothing; it must be an object the function
  walks and assigns into.

## Test shape
```js
const { FuzzedDataProvider } = require("@jazzer.js/core");
const target = require("<the installed library entry>");
module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data);
  // derive input from provider, but ALSO hard-code the property-triggering input above as a fallback
  // so the very first run already triggers the behavior. Call the function of interest directly.
};
```

## Per library
1. `npm install <name>@<ver>` in a scratch dir; open the file at the target `file:line:col`.
2. Read the function there and find the shortest public API that reaches that line.
3. Write the test per behavior A or B above.
4. If you can, build the runner image `docker build -t proofhound/jazzerjs:latest C:\dev\proofhound\docker\jazzerjs\`
   and run the test; confirm the runner's report appears (a timeout for A, a shared-prototype report for
   B). Iterate until it triggers.

## Libraries (name@version — target line — behavior — reference)
1. ajv@5.2.2 — util.js:143:14 — A (slow-regex) — CVE-2020-15366
2. amqp-match@0.0.0 — index.js:4:17 — A (slow-regex)
3. ansi-html@0.0.7 — index.js:62:18 — A (slow-regex) — CVE-2021-23424
4. axios@0.21.0 — utils.js:190:34 — A (slow-regex) — CVE-2021-3749
5. brace-expansion@1.1.6 — index.js:109:35 — A (slow-regex) — CVE-2017-18077
6. browserslist@4.16.4 — index.js:333:29 — A (slow-regex) — CVE-2021-23364
7. charset@1.0.0 — charset.js:59:26 — A (slow-regex) — CVE-2017-16098
8. chrono-node@2.2.3 — chrono.js:42:29 — A (slow-regex) — CVE-2021-23371
9. 101@1.0.0 — index.js:32:16 — B (shared-prototype) — CVE-2021-25943
10. algoliasearch-helper@3.6.0 — src/functions/merge.js:38:19 — B (shared-prototype) — CVE-2021-23433
11. arr-flatten-unflatten@1.1.4 — unflatten.js:17:16 — B (shared-prototype) — CVE-2020-7713
12. asciitable.js@1.0.2 — asciitable.umd.js:50:104 — B (shared-prototype) — CVE-2020-7771
13. assign-deep@1.0.0 — index.js:22:23 — B (shared-prototype) — CVE-2019-10745
14. aurelia-path@1.1.0 — dist/commonjs/aurelia-path.js:163:42 — B (shared-prototype) — CVE-2021-41097
15. @aws-sdk/shared-ini-file-loader@1.0.0-rc.8 — src/index.ts:108:20 — B (shared-prototype) — CVE-2020-28472
16. bmoor@0.8.11 — src/core.js:194:18 — B (shared-prototype) — CVE-2020-7736

## Output — one JSON file per library
Save to `C:\dev\proofhound\training\data\distill-v5\<name>_<ver>__<shortid>.json` (replace `/` and `@`
in the name with `-`; `<shortid>` = first 10 hex chars of any hash of the target line). Schema:
```json
{
  "finding_id": "<shortid>",
  "case": "<name>_<ver>",
  "vuln_class": "redos" | "prototype-pollution",
  "sink": "<file:line:col>",
  "call_chain_analysis": "<entry function -> each intermediate call -> the target line>",
  "argument_reasoning": "<why your input shape triggers the behavior at the target line>",
  "final_harness": "<the complete JS test, module.exports.fuzz>",
  "fuzz_output_summary": "<the runner report you saw, or 'not run' if you could not build>",
  "attempts_before_success": <int>,
  "lessons": "<one line: what made the runner's check trigger>"
}
```
Keep the `vuln_class` values exactly as shown (they are just the dataset's category labels). The most
important field is `final_harness`, and it must follow the technique above — direct call, repetitive
slow-input string for A, a real object with a `__proto__`/`constructor.prototype` key for B.

--- PROMPT END ---
