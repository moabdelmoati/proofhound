// Jazzer.js harness for arpping@2.0.0 command-injection at index.js:120:13.
//
// Call chain:
//   new Arpping({...})            // constructor, timeout must be in 1..60
//     -> prototype.ping(range)    // range must be a non-empty array
//        -> range.forEach(ip => exec(`ping ${flag} ${this.timeout} ${ip}`, cb))
//                                        ^^ sink: unescaped ip in a shell command
//
// The one fuzz-controlled argument (an "ip" entry) is spliced into the shell
// command without any sanitation, so Jazzer.js's CommandInjection detector
// fires as soon as the fuzzer places its sentinel ("jaz_zer") into the entry.

const { FuzzedDataProvider } = require("@jazzer.js/core");
const Arpping = require("/work/target/index.js");

module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data);
  // Full fuzzer control over the shell-injected substring. Node's exec()
  // rejects strings that contain NUL bytes with a TypeError that is NOT the
  // bug we are after, so we strip NULs here to keep the fuzzer searching for
  // the real detector sentinel instead of exiting on that TypeError.
  const injected = provider.consumeRemainingAsString().replace(/\u0000/g, "");

  // Avoid the discover() cache gate and keep timeout valid so the constructor
  // reaches ping().
  const a = new Arpping({ timeout: 5, useCache: false, includeEndpoints: false });

  try {
    // ping() calls exec() synchronously for each range entry; Jazzer's hook on
    // child_process.exec inspects the command string before the OS process is
    // spawned, so detection happens even though the exec callback is async.
    a.ping([injected]);
  } catch (err) {
    // Re-throw Jazzer bug-detector reports; swallow only target-domain errors
    // (invalid timeout, exec arg validation, etc.) so the fuzzer keeps going.
    if (err && err.name && String(err.name).includes("Jazzer")) throw err;
    if (err && typeof err.message === "string"
        && /command injection|path traversal|prototype pollution/i.test(err.message)) {
      throw err;
    }
  }
};
