// Jazzer.js harness for async-git@1.13.1 command-injection at lib/reset/index.js:11:16.
//
// Call chain:
//   require("/work/target/lib/reset/index.js")   // this file IS reset()
//     reset(destination, { hard = true })        // destination must be a truthy string
//       -> exec(`git reset ${JSON.stringify(destination)} ${hard ? '--hard' : ''}`)
//                                                   ^^ sink: destination is only JSON.stringified,
//                                                      which escapes `"` and `\` but NOT shell
//                                                      metacharacters. Inside the surrounding
//                                                      double-quoted shell string, backticks and
//                                                      $(…) still run as command substitutions.
//
// The fuzzer-controlled `destination` string flows straight into the exec()
// command, so Jazzer.js's CommandInjection detector fires as soon as libFuzzer
// places its sentinel ("jaz_zer") into the string. `jaz_zer` has no character
// that JSON.stringify escapes, so the sentinel survives into the final command.

const { FuzzedDataProvider } = require("@jazzer.js/core");
const reset = require("/work/target/lib/reset/index.js");

module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data);
  // Give the fuzzer control of the shell-injected substring. Node's exec()
  // rejects strings containing NUL bytes with a TypeError that is NOT the
  // bug we are after, so we strip NULs to keep the detector sentinel evolving.
  const destination = provider.consumeRemainingAsString().replace(/\u0000/g, "");

  // reset() short-circuits on falsy destinations and throws TypeError for
  // non-string, non-number destinations, so hand it a truthy string.
  // Jazzer's child_process.exec hook inspects the command string before the
  // shell runs, so the detector fires even though exec is async and we don't
  // await the returned promise.
  let p;
  try {
    p = reset(destination, { hard: true });
  } catch (err) {
    if (err && err.name && String(err.name).includes("Jazzer")) throw err;
    return;
  }
  // Swallow the async-execute rejection (git reset will exit non-zero);
  // that is unrelated to the CommandInjection detector.
  if (p && typeof p.catch === "function") {
    p.catch(() => {});
  }
};
