// Jazzer.js harness for blamer@0.1.13 prototype-pollution at src/vcs/git.js:40:20.
//
// Where the sink actually is.
// The SAST finding anchors on `result[line.line] = line;` at git.js:40.
// `line.line` is bound to the 5th capture group of
//   /(.+)\s+\((.+)\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} (\+|\-)\d{4})\s+(\d+)\)(.*)/
// which only matches `\d+`, so the sink's own key can never be `__proto__`
// through any legit `git blame` output. The attacker-reachable
// prototype-pollution write in the same function is one line later:
//
//   res[file] = result;   // git.js:43
//
// where `file` is the exported-function parameter. Jazzer's
// Prototype-Pollution detector only reports changes to BASIC_OBJECTS
// (Object/Array/String/Number/Boolean/Function) in its afterEach hook, so a
// local `res['__proto__'] = {...}` write slips past the default check. To
// catch it we enable `instrumentAssignmentsAndVariableDeclarations()`, which
// rewrites every assignment to call `PrototypePollution.detectPrototypePollution`
// on the assignment's base identifier right after the write. The detector
// then JSON-stringifies `res.__proto__` and reports anything that is not
// `null`, `{}`, `[]`, `""`, booleans, `0`, or a user-whitelisted value.
//
// Call chain.
//   require("/work/target/src/index.js")              // module.exports = Blamer
//     -> new Blamer('git').blameByFile(file, args)    // Blamer.js:15
//        -> blamerVCS.git(file, args)                 // ./vcs/git.js module.exports
//           -> exec('git blame ' + args + ' ' + realFile, {cwd}, cb)   // git.js:24
//              -> stubExec invokes cb(null, "<one-line>", "")
//                 lines = stdout.split('\n')
//                 forEach -> convertStringToObject (regex passes, matches[5]='42')
//                 result['42'] = {rev,author,date,line:'42'}      // git.js:40
//                 res[file] = result                              // git.js:43 SINK
//                   with file === '__proto__', Jazzer's
//                   detectPrototypePollution(res, 'res') fires
//
// Preconditions.
//   1. Enable instrumentAssignmentsAndVariableDeclarations BEFORE any
//      instrumented module (blamer -> git.js) is required, so the AST
//      transform fires on git.js:43.
//   2. Stub `child_process.exec` BEFORE git.js is required, because git.js
//      captures `exec = require('child_process').exec` at module scope.
//   3. Feed stdout that satisfies the regex, otherwise `matches[1]` throws
//      TypeError and the sink is never reached. We hard-code one line.
//   4. Jazzer's PP detector seeds the fuzzer dictionary with "__proto__",
//      "constructor", "prototype", "constructor.prototype", so a short
//      consumeString() draw converges on the attack key within a few iterations.

// (1) Configure PP detector before loading the target module so git.js is
// instrumented for per-assignment checks.
require("@jazzer.js/bug-detectors")
  .getBugDetectorConfiguration("prototype-pollution")
  ?.instrumentAssignmentsAndVariableDeclarations()
  ?.addExcludedExactMatch("{}");

// (2) Stub child_process.exec before blamer's git.js captures it.
const child_process = require("child_process");
const BLAME_LINE =
  "deadbeefcafe (Author 2024-01-01 00:00:00 +0000 42) code line\n";
child_process.exec = function fakeExec(command, options, cb) {
  // exec(cmd, options, cb) — git.js:24 uses the 3-arg form.
  // Deliver on next tick so the Promise constructor finishes installing resolvers.
  process.nextTick(() => cb(null, BLAME_LINE, ""));
  return { kill() {} };
};

const { FuzzedDataProvider } = require("@jazzer.js/core");
const Blamer = require("/work/target/src/index.js");

module.exports.fuzz = async function (data) {
  const provider = new FuzzedDataProvider(data);
  // `file` becomes the attacker key written to `res`. The detector dictionary
  // contains `"__proto__"`, `"constructor"`, `"prototype"`, so the fuzzer
  // reaches the pollution path in a handful of runs.
  const file = provider.consumeString(32);
  const args = provider.consumeString(16);

  const blamer = new Blamer("git");
  try {
    await blamer.blameByFile(file, args);
  } catch (err) {
    // Re-throw Jazzer findings (Prototype Pollution, etc.); swallow only
    // target-domain errors so the fuzzer keeps evolving the attack key.
    if (err && err.name && String(err.name).includes("Jazzer")) throw err;
    if (
      err &&
      typeof err.message === "string" &&
      /prototype pollution/i.test(err.message)
    ) {
      throw err;
    }
  }
};
