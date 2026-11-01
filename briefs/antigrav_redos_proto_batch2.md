# Antigravity / Gemini task (batch 2) — property-based regression tests for regex performance & object-merge behavior

Paste everything between `--- PROMPT START ---` and `--- PROMPT END ---` into Gemini (Antigravity) with
the `C:\dev\proofhound` repo open. It writes 26 JSON files. Tell Claude Code "batch 2 done" when finished.

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
- Do **not** stub `child_process`/`exec` or other internals to feed the string in — prefer the shortest
  direct call path. One match must take seconds, which the runner reports as a timeout.

**B. Deep-merge writing to a shared prototype (shared-state property).** Some libraries have a recursive
merge/clone/set that, given an **object** with a specially-named key, writes onto the shared
`Object.prototype`. To make the runner's shared-prototype check fire:
- Pass a real **object** (not a string) whose key is `__proto__` or a `constructor` → `prototype` path,
  e.g. `JSON.parse('{"__proto__":{"touched":true}}')`, into the merge/set/clone function of interest.
- After the call, a brand-new `{}` must show the added property (`({}).touched === true`). Passing the
  string `"__proto__"` does nothing; it must be an object the function walks and assigns into.

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

## How to work each library
1. `npm install <name>@<ver>` in a scratch dir; open the file at the target `file:line:col`.
2. Read the function there and find the shortest public API that reaches that line.
3. Write the test per behavior A or B above.
4. If you can, build `docker build -t proofhound/jazzerjs:latest C:\dev\proofhound\docker\jazzerjs\` and
   run it; confirm the runner's report appears (a timeout for A, a shared-prototype report for B).

## Libraries (name@version — target line — behavior — reference)
1. clean-css@4.1.10 — validator.js:418:20 — A
2. codemirror@5.58.0 — jasmineAsyncInstall.js:106:37 — A — CVE-2020-7760
3. color-string@1.5.4 — index.js:154:21 — A — CVE-2021-29060
4. colors-cli@1.0.25 — color-safe.js:60:23 — A
5. content-type-parser@1.0.1 — content-type-parser.js:61:46 — A
6. content@3.0.5 — index.js:84:34 — A
7. d3-color@2.0.0 — d3-color.js:221:27 — A
8. date-and-time@0.14.1 — date-and-time.js:141:27 — A — CVE-2020-26289
9. dirty-json@0.4.0 — utils.js:391:28 — A
10. ducktype@1.2.0 — ducktype.js:165:24 — A
11. email-existence@0.1.5 — index.js:8:19 — A
12. ethers@5.2.0 — fixednumber.js:97:36 — A
13. express-validators@1.0.3 — index.js:615:23 — A — CVE-2020-7767
14. fast-csv@4.3.5 — Parser.js:69:64 — A — CVE-2020-26256
15. forwarded@0.1.0 — index.js:27:6 — A — CVE-2017-16118
16. fresh@0.5.0 — index.js:61:40 — A — CVE-2017-16119
17. github-url-to-object@4.0.2 — commonjs.js:19:27 — A
18. glob-parent@5.0.0 — index.js:20:17 — A — CVE-2021-35065
19. highlight.js@10.4.0 — core.js:858:36 — A
20. hosted-git-info@3.0.0 — index.js:44:27 — A — CVE-2021-23362
21. aurelia-path@1.1.0 — dist/commonjs/aurelia-path.js:163:42 — B — CVE-2021-41097
22. bodymen@1.0.0 — dist/index.js:44:26 — B — CVE-2019-10792
23. @brikcss/merge@1.3.0 — merge/dist/lib/merge.js:2:1599 — B
24. cached-path-relative@1.0.1 — lib/index.js:39:19 — B — CVE-2018-16472
25. changeset@0.1.0 — index.js:81:25 — B — CVE-2021-25915
26. class-transformer@0.1.1 — TransformOperationExecutor.ts:163:46 — B — CVE-2020-7637

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
Keep `vuln_class` exactly as shown (A → "redos", B → "prototype-pollution"; they are dataset labels).
The most important field is `final_harness`, and it must follow the technique above — a direct call with
a repetitive slow-input string for A, and a real object with a `__proto__`/`constructor.prototype` key for B.

--- PROMPT END ---
