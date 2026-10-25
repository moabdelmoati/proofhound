// Jazzer.js harness for adb-driver@0.1.8 command-injection at build/AdbDriver.js:26:25.
//
// Call chain:
//   execADBCommand(command)                       // module export (build/AdbDriver.js:17)
//     if (!systemAdbExist) {                      // true in sandbox: no 'adb' on PATH
//       cmd = command.split(' ');
//       cmd[0] = '"${binFile}"';                  // first token always replaced
//       execCmd = cmd.join(' ');
//     } else execCmd = command;
//     exec(execCmd, option || {stdio:'inherit'}, cb)   // sink: 26:25
//
// Jazzer's CommandInjection detector hooks child_process.exec and fires when its
// 'jaz_zer' sentinel appears anywhere in the command string. In the sandbox
// `which.sync('adb')` is null, so cmd[0] gets overwritten by the binary path.
// We give the fuzzer control of the ENTIRE command string and prepend a single
// space so the sentinel, when the fuzzer evolves it, lives in a token with
// index >= 1 and survives the first-token replacement.

const { FuzzedDataProvider } = require("@jazzer.js/core");
const AdbDriver = require("/work/target/build/AdbDriver.js");

module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data);
  // Node's child_process.exec rejects strings with NUL bytes before Jazzer's
  // hook can score the input, so strip them to keep libFuzzer evolving toward
  // the detector sentinel instead of exiting on the TypeError.
  const injected = provider.consumeRemainingAsString().replace(/\u0000/g, "");

  // Leading space keeps the sentinel out of cmd[0], which execADBCommand
  // overwrites with the (missing) adb binary path.
  const command = " " + injected;

  try {
    // execADBCommand returns a Promise; the exec() hook runs synchronously
    // inside the Promise executor so the detector fires before the Promise
    // resolves/rejects. The outer .catch(err => err) in execADBCommand turns
    // the exec error into a resolved value, so there is nothing async to await
    // for detection to happen.
    AdbDriver.execADBCommand(command);
  } catch (err) {
    // Re-throw Jazzer bug-detector reports; swallow only target-domain errors.
    if (err && err.name && String(err.name).includes("Jazzer")) throw err;
    if (err && typeof err.message === "string"
        && /command injection|path traversal|prototype pollution/i.test(err.message)) {
      throw err;
    }
  }
};
