// Jazzer.js harness for buns@1.1.6 command-injection at lib/index.js:678:9.
//
// Call chain:
//   require("/work/target/lib/index.js")      // module exports `buns` methods
//     -> exports.install(requestedModule)     // lib/index.js:652
//        -> name = requestedModule
//        -> command = 'npm i' + ' --save-dev ' + name   // lib/index.js:668..670
//        -> exec(command)                               // sink: lib/index.js:678:9
//
// `exec` is bound to `child_process.execSync` at the top of lib/index.js, so a
// synchronous shell command is launched and Jazzer.js's CommandInjection bug
// detector fires on the exec hook before the real process starts.
//
// Preconditions:
//   - `requestedModule` must be truthy so we hit the `--save-dev <name>` branch
//     rather than the else branch (which reads __buns/package.json and would
//     throw ENOENT before reaching the sink).
//   - Node's exec() rejects strings containing NUL bytes with a TypeError, so
//     we strip NULs from the fuzz input to keep the fuzzer searching for the
//     real detector sentinel.
//   - Jazzer.js's CommandInjection detector plants the sentinel "jaz_zer" into
//     fuzz input via libFuzzer's compare/dictionary interception, then flags
//     any exec/execSync whose command contains that sentinel.

const { FuzzedDataProvider } = require("@jazzer.js/core");
const buns = require("/work/target/lib/index.js");

module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data);
  // Hand the fuzzer full control over the substring spliced into the shell
  // command. Strip NUL so Node's exec() does not reject the input with a
  // TypeError (which would exit the fuzz target before the sentinel evolves).
  const name = provider.consumeRemainingAsString().replace(/\u0000/g, "");

  // install() tolerates missing buns.json: the top-level config load catches
  // ENOENT and sets configExists=false, but install() itself does not gate on
  // configExists, so the sink is reachable with no on-disk state.
  try {
    buns.install(name);
  } catch (err) {
    // Re-throw Jazzer bug-detector reports; swallow only target-domain errors
    // (e.g. the npm process failing after Jazzer's hook has run) so the fuzzer
    // keeps evolving the sentinel.
    if (err && err.name && String(err.name).includes("Jazzer")) throw err;
    if (err && typeof err.message === "string"
        && /command injection|path traversal|prototype pollution/i.test(err.message)) {
      throw err;
    }
  }
};
