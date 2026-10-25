// Jazzer.js harness for apex-publish-static-files@2.0.0 command-injection at index.js:54:25.
//
// Call chain:
//   require("/work/target/index.js").publish(opts)
//     -> execSync(
//          '"' + opts.sqlclPath + '"' +
//          ' ' + opts.connectString +                              // <- fuzzer-controlled, raw
//          ' @"' + path.resolve(__dirname, 'lib/script') + '"' +
//          ' "' + path.resolve(__dirname, 'lib/distUpload.js') + '"' +
//          ' "' + path.resolve(opts.directory) + '"' +
//          ' ' + opts.appID +
//          ' "' + opts.destination + '"' +
//          ' "' + opts.pluginName + '"'
//        )                                                         // sink: index.js:54:25
//
// `connectString` is concatenated into the shell string with only a space on each side -- no
// quoting, no escaping -- so any bytes we put there (including Jazzer's "jaz_zer" sentinel)
// reach child_process.execSync unmodified. The Jazzer.js CommandInjection detector plants that
// sentinel via libFuzzer's compare-trap dictionary; the first iteration whose connectString
// contains "jaz_zer" fires the detector before the shell runs.
//
// Preconditions on reaching line 54:
//   * opts.connectString, opts.directory, opts.appID must all be defined (lines 18/22/26).
//   * fs.existsSync(opts.directory) must be true (line 34). We point it at an empty directory
//     we create under the target package.
//   * opts.destination defaults to 'application', so the plugin branch at line 30 is skipped
//     and we don't need a pluginName.
// `execSync` itself will throw (there is no `sql` binary on PATH), and publish() wraps the whole
// try-block in a catch that console.errors any error and returns false. That is fine: Jazzer's
// CommandInjection hook runs synchronously before execSync spawns the shell and records the
// finding via the per-iteration bug-detector state, so the finding is reported even if the
// synchronous FuzzerError the hook throws is caught by publish()'s own try/catch.

const path = require("path");
const { FuzzedDataProvider } = require("@jazzer.js/core");
const apex = require("/work/target/index.js");

// A directory that is guaranteed to exist for fs.existsSync(opts.directory).
const DIRECTORY = path.join(__dirname, "..", "target", "empty-dir");

module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data);
  // Give the fuzzer control of the shell-injected substring. Node's child_process rejects
  // strings containing NUL bytes with a TypeError that is NOT the bug we are after, so we
  // strip NULs to keep the detector sentinel evolving.
  const connectString = provider.consumeRemainingAsString().replace(/\u0000/g, "");

  try {
    apex.publish({
      connectString: connectString,
      directory: DIRECTORY,
      appID: "100",
      destination: "application", // default branch -- no pluginName needed
      sqlclPath: "sql",
    });
  } catch (err) {
    // publish() internally catches its own exec error; the only error that reaches us is
    // Jazzer's own FuzzerError when the detector short-circuits -- re-throw so the fuzz
    // iteration terminates immediately on the sentinel hit.
    if (err && err.name && String(err.name).includes("Jazzer")) throw err;
  }
};
