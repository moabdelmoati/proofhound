# Antigravity / Gemini task (batch 3) — property-based regression tests for regex performance & object-merge behavior

Paste everything between `--- PROMPT START ---` and `--- PROMPT END ---` into Gemini (Antigravity) with
the `C:\dev\proofhound` repo open. It writes 30 JSON files. Tell Claude Code "batch 3 done" when finished.

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

## Keep the repo clean (important)
Do ALL `npm install`s, unpacking, and throwaway test scripts in a temp folder **outside** the repo
(your OS temp, e.g. `%TEMP%\gemini_work`), and delete them when done. Do **not** create `node_modules`,
test files, or a `scratch/` folder anywhere inside `C:\dev\proofhound`. The **only** files you write
into the repo are the 30 JSON outputs under `training\data\distill-v5\`.

## How to work each library
1. `npm install <name>@<ver>` in a temp folder outside the repo; open the file at the target `file:line:col`.
2. Read the function there and find the shortest public API that reaches that line.
3. Write the test per behavior A or B above.
4. If you can, build `docker build -t proofhound/jazzerjs:latest C:\dev\proofhound\docker\jazzerjs\` and
   run it; confirm the runner's report appears (a timeout for A, a shared-prototype report for B). Put
   any harness/corpus files you run in the temp folder, not in the repo.

## Libraries (name@version — target line — behavior)
1. html-parse-stringify2@2.0.1 — parse.js:39:10 — A
2. html-parse-stringify@2.0.0 — html-parse-stringify.js:1:1428 — A
3. htmlparser@1.7.7 — htmlparser.js:226:72 — A
4. is-email@1.0.0 — index.js:13:18 — A
5. is-my-json-valid@2.20.1 — index.js:172:21 — A
6. is-svg@4.2.2 — index.js:21:13 — A
7. is-url@1.2.2 — index.js:22:18 — A
8. jspdf@2.1.1 — jspdf.node.min.js:86:5935 — A
9. locutus@2.0.10 — inet_pton.js:30:9 — A
10. lodash@4.17.4 — lodash.js:1172:29 — A
11. marked@0.3.6 — marked.js:662:31 — A
12. method-override@2.0.0 — index.js:113:40 — A
13. millisecond@0.1.1 — index.js:43:21 — A
14. mime@1.4.0 — mime.js:70:18 — A
15. minimatch@3.0.0 — minimatch.js:167:14 — A
16. mobile-detect@1.3.6 — mobile-detect.js:375:32 — A
17. moment@2.18.1 — moment.js:2364:31 — A
18. ms@0.7.0 — index.js:41:135 — A
19. natural@5.1.0 — dice_coefficient.js:54:28 — A
20. no-case@2.3.1 — no-case.js:34:6 — A
21. normalize-url@6.0.0 — index.js:12:68 — A
22. npm-user-validate@1.0.0 — npm-user-validate.js:48:11 — A
23. nth-check@2.0.0 — parse.js:22:26 — A
24. papaparse@5.1.1 — papaparse.js:1142:14 — A
25. aurelia-path@1.1.0 — dist/commonjs/aurelia-path.js:163:42 — B
26. component-flatten@1.0.1 — index.js:56:26 — B
27. confinit@0.3.0 — index.ts:112:15 — B
28. confucious@0.0.12 — confucious.js:48:21 — B
29. connie@0.1.0 — lib/connie-lang.js:43:28 — B
30. convict@6.0.0 — src/main.js:565:24 — B

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
