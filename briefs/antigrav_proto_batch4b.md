# Antigravity / Gemini task (batch 4b) — property-based regression tests

Paste between `--- PROMPT START ---` and `--- PROMPT END ---` into Gemini (Antigravity) with the
`C:\dev\proofhound` repo open. It writes up to 35 JSON files. If Gemini stops early, paste again —
it skips libraries whose JSON already exists. Tell Claude Code "batch 4b done" when finished.

--- PROMPT START ---

You are writing property-based regression tests for npm libraries to capture a known behavior so a model
can learn to reproduce it. Each test is a Jazzer.js property test (`module.exports.fuzz`). The goal is not
just to call the function of interest, but to make the test runner's built-in check actually trigger —
reaching the line is easy; making the property fail is the point.

## Behavior B: Deep-merge writing to a shared prototype
- Some libraries have a recursive merge/clone/set that, given an object with a specially-named key, writes
  onto the shared Object.prototype. To make the runner's shared-prototype check fire: pass a real object
  (not a string) whose key is __proto__ or a constructor -> prototype path, e.g.
  JSON.parse('{"__proto__":{"touched":true}}'), into the merge/set/clone function.
- After the call, a fresh {} must show the property (({}).touched === true). A plain string does nothing.

## Test shape
```js
const { FuzzedDataProvider } = require("@jazzer.js/core");
const target = require("<the installed library entry>");
module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data);
  // derive input from provider, but ALSO hard-code the property-triggering input above as a fallback
  // so the first run already triggers the behavior. Call the function of interest directly.
};
```

## Keep the repo clean (important)
Do ALL npm installs and throwaway files in a temp folder OUTSIDE the
repo (%TEMP%\gemini_work) and delete them when done. Do NOT create node_modules or test files inside
C:\dev\proofhound. The only files you write into the repo are the JSON outputs under
training\data\distill-v5\.

## How to work each library
1. npm install <name>@<ver> in the temp folder; open the file at the target
file:line:col.
2. Find the shortest public API that reaches that line; write the test per the behavior.
3. If you can, build & run docker build -t proofhound/jazzerjs:latest C:\dev\proofhound\docker\jazzerjs\nand confirm the runner's report appears.

## Libraries (name@version — target line — behavior)
1. aurelia-path@1.1.0 — dist/commonjs/aurelia-path.js:163:42 — B
2. @cookiex/deep@0.0.6 — deep/dist/assigner.js:13:31 — B
3. copy-props@2.0.4 — index.js:197:14 — B
4. deap@1.0.0 — lib/connie-lang.js:35:28 — B
5. decal@2.0.0 — src/utils/set.js:62:21 — B
6. decal@2.1.3 — src/utils/extend.js:50:62 — B
7. deep-defaults@1.0.5 — lib/index.js:16:21 — B
8. deep-extend@0.5.0 — lib/deep-extend.js:117:17 — B
9. deep-get-set@1.1.0 — index.js:30:16 — B
10. deep-override@1.0.0 — src/index.js:53:23 — B
11. deep-set@1.0.0 — index.js:33:31 — B
12. deephas@1.0.5 — deepHas.js:65:20 — B
13. deeply@3.0.0 — lib/reduce_object.js:19:14 — B
14. deepmergefn@1.1.0 — index.js:12:30 — B
15. deepref@1.1.1 — index.js:29:28 — B
16. deeps@1.4.5 — index.js:226:94 — B
17. defaults-deep@0.2.0 — index.js:20:16 — B
18. defaults-deep@0.2.4 — index.js:26:21 — B
19. doc-path@2.0.0 — src/path.js:54:27 — B
20. dot-notes@3.2.0 — lib/create.js:43:19 — B
21. dot-object@2.1.2 — index.js:415:25 — B
22. dot-prop@2.0.0 — index.js:32:14 — B
23. dotty@0.0.1 — lib/index.js:147:17 — B
24. dset@1.0.0 — dist/dset.js:6:18 — B
25. @eivifj/dot@1.0.2 — dot/index.js:22:13 — B
26. eivindfjeldstad-dot@0.0.1 — index.js:20:13 — B
27. expand-hash@1.0.1 — index.js:19:13 — B
28. extend-merge@1.0.5 — base-extend.js:41:21 — B
29. extend@3.0.1 — index.js:77:20 — B
30. @fabiocaccamo/utils.js@0.17.0 — utils.js/dist/utils.js:2365:33 — B
31. fast-json-patch@2.0.4 — lib/core.js:28:18 — B
32. field@1.0.1 — lib/field.js:50:20 — B
33. @firebase/util@0.3.2 — util/src/deepCopy.ts:68:49 — B
34. @firebase/util@0.3.3 — util/src/deepCopy.ts:68:49 — B
35. flat-wrap@1.0.2 — index.js:193:43 — B

## Output — one JSON file per library
Save to
C:\dev\proofhound	raining\data\distill-v5\<name>_<ver>__<shortid>.json (replace / and @ with -;
<shortid> = first 10 hex of any hash of the target line). Schema:
```json
{"finding_id":"<shortid>","case":"<name>_<ver>","vuln_class":"prototype-pollution","sink":"<file:line:col>",
"call_chain_analysis":"<entry -> intermediate -> target line>","argument_reasoning":"<why it triggers>",
"final_harness":"<complete JS test>","fuzz_output_summary":"<runner report or 'not run'>",
"attempts_before_success":<int>,"lessons":"<one line>"}
```
The most important field is final_harness, following the technique above.

--- PROMPT END ---
