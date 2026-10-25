// Jazzer.js harness for bestzip@2.1.6 command-injection at lib/bestzip.js:27:27.
//
// Call chain:
//   bestzip.nativeZip({ destination, source, cwd })
//     -> const command = `zip --quiet --recurse-paths ${destination} ${sources}`
//     -> cp.exec(command, { stdio: "inherit", cwd })   // sink
//
// `sources` is `options.source` (string) or the joined array; both splice into
// the shell command string with no sanitation. Jazzer.js's CommandInjection
// detector hooks child_process.exec and inspects the command string
// synchronously, so detection happens whether or not the OS `zip` binary
// exists in the sandbox. We call nativeZip directly (it is exported) rather
// than the top-level `zip()`, which gates on hasNativeZip() / which.sync("zip").

const { FuzzedDataProvider } = require("@jazzer.js/core");
const bestzip = require("/work/target/node_modules/bestzip");

module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data);
  // Full fuzzer control over the shell-injected substring. Node's exec()
  // rejects strings containing NUL bytes with a TypeError that is not the
  // bug under test, so we strip NULs to keep the sentinel search going.
  const injected = provider.consumeRemainingAsString().replace(/\u0000/g, "");

  try {
    // nativeZip() builds `zip --quiet --recurse-paths <destination> <sources>`
    // and calls child_process.exec(command, ...) synchronously. Place the
    // fuzzer-controlled string into `source` so it appears unescaped in the
    // command string.
    const p = bestzip.nativeZip({
      destination: "out.zip",
      source: injected,
      cwd: "/tmp",
    });
    // The promise rejects asynchronously when the (missing) `zip` binary
    // emits an error; the detector has already observed the exec call by
    // the time this runs. Swallow the async rejection so the fuzzer keeps
    // searching for the sentinel.
    if (p && typeof p.catch === "function") p.catch(() => {});
  } catch (err) {
    if (err && err.name && String(err.name).includes("Jazzer")) throw err;
    if (err && typeof err.message === "string"
        && /command injection|path traversal|prototype pollution/i.test(err.message)) {
      throw err;
    }
  }
};
