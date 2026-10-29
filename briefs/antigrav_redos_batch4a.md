# Antigravity / Gemini task (batch 4a) — property-based regression tests

Paste between `--- PROMPT START ---` and `--- PROMPT END ---` into Gemini (Antigravity) with the
`C:\dev\proofhound` repo open. It writes up to 35 JSON files. If Gemini stops early, paste again —
it skips libraries whose JSON already exists. Tell Claude Code "batch 4a done" when finished.

--- PROMPT START ---

You are writing property-based regression tests for npm libraries to capture a known behavior so a model
can learn to reproduce it. Each test is a Jazzer.js property test (`module.exports.fuzz`). The goal is not
just to call the function of interest, but to make the test runner's built-in check actually trigger —
reaching the line is easy; making the property fail is the point.

## Behavior A: Super-linear regex matching
- Some libraries contain a regex whose matching time grows super-linearly on certain strings. To make
  the Jazzer runner's per-input timeout fire: build a long, highly repetitive string with one non-matching
  break at the end, e.g. "a".repeat(5000) + "!" — adapt the character/shape to the regex at the target line
  so one .test()/.match()/.replace() takes several seconds.
- Pass that string directly into the parameter that reaches the regex; call the exported function as
  directly as the public API allows. Do not stub child_process/exec or other internals.

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
1. parsejson@0.0.3 — index.js:20:38 — A
2. path-parse@1.0.6 — index.js:59:22 — A
3. platform@1.3.4 — platform.js:117:10 — A
4. postcss@8.0.0 — previous-map.js:57:27 — A
5. printf@0.6.0 — printf.js:14:21 — A
6. prompts@2.4.0 — strip.js:10:40 — A
7. prototype@0.0.5 — String.js:84:17 — A
8. ramda@0.27.1 — trim.js:33:35 — A
9. react-native@0.63.0-rc.0 — jasmineAsyncInstall.js:106:37 — A
10. remove-markdown@0.3.0 — index.js:48:8 — A
11. revalidator@0.3.1 — revalidator.js:289:19 — A
12. rgb2hex@0.1.0 — index.js:25:73 — A
13. sanitize@2.0.0 — Sanitizer.js:148:37 — A
14. semver-regex@3.1.1 — jasmineAsyncInstall.js:106:37 — A
15. simple-markdown@0.7.2 — simple-markdown.js:492:26 — A
16. slug@0.9.1 — slug.js:64:21 — A
17. sshpk@1.13.1 — ssh.js:28:18 — A
18. ssri@8.0.0 — index.js:123:31 — A
19. string@3.3.3 — string.js:618:68 — A
20. terminal-kit@2.1.0 — misc.js:185:35 — A
21. three@0.122.0 — three.js:6333:46 — A
22. timespan@2.3.0 — time-span.js:385:30 — A
23. tmpl@1.0.0 — tmpl.js:8:9 — A
24. tough-cookie@2.3.2 — cookie.js:330:23 — A
25. trim-off-newlines@1.0.0 — index.js:6:13 — A
26. trim@0.0.1 — index.js:5:14 — A
27. truncate@2.0.0 — truncate.js:47:33 — A
28. ua-parser-js@0.7.22 — ua-parser.js:98:42 — A
29. underscore.string@3.3.4 — unescapeHTML.js:5:26 — A
30. uri-js@2.1.1 — uri.js:175:33 — A
31. url-regex@5.0.0 — jasmineAsyncInstall.js:106:37 — A
32. urlregex@0.5.0 — jasmineAsyncInstall.js:106:37 — A
33. valid-email@0.0.1 — utils.js:391:28 — A
34. vant@2.12.11 — email.js:9:14 — A
35. ws@7.0.0 — jasmineAsyncInstall.js:106:37 — A

## Output — one JSON file per library
Save to
C:\dev\proofhound	raining\data\distill-v5\<name>_<ver>__<shortid>.json (replace / and @ with -;
<shortid> = first 10 hex of any hash of the target line). Schema:
```json
{"finding_id":"<shortid>","case":"<name>_<ver>","vuln_class":"redos","sink":"<file:line:col>",
"call_chain_analysis":"<entry -> intermediate -> target line>","argument_reasoning":"<why it triggers>",
"final_harness":"<complete JS test>","fuzz_output_summary":"<runner report or 'not run'>",
"attempts_before_success":<int>,"lessons":"<one line>"}
```
The most important field is final_harness, following the technique above.

--- PROMPT END ---
