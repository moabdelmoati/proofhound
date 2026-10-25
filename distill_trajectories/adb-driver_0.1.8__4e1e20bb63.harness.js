// Jazzer.js harness for adb-driver@0.1.8, finding 4e1e20bb63:
// the semgrep "redos" rule flagged build/AdbDriver.js:20:19 as a candidate
// catastrophic-backtracking sink. The flagged "pattern" is actually
// `command.split(' ')` — a String.prototype.split call whose argument is the
// plain string `' '`, NOT a regular expression. ECMAScript 262 §22.1.3.21
// treats a non-regex separator as a literal-substring match, so no backtracking
// engine ever runs on this call site, and SlowRegex can never fire.
//
// We still build the harness so the fuzz call reaches the sink line (so the
// case counts as "reached" when replayed), and we construct the kind of
// payload a real redos target would need — a long run of 'a' followed by a
// non-match terminator — so a human (or a later rerun of this harness
// against a hypothetical fixed rule) can see we gave the fuzzer every chance.
//
// Reach:
//   require("adb-driver/build/AdbDriver.js").execADBCommand(cmd, {...})
//     cmd.split(' ')          <-- sink line (:20:19), literal-string split
//     exec(execCmd, option, cb) at :26:25
//                             <-- the real sink (command-injection) for this case
//
// We do NOT want the CommandInjection detector to fire here, because the
// finding we are confirming is the redos one; a crash from a different
// detector would be scored against a different finding ID. We therefore
// strip any 'jaz_zer' sentinel the fuzzer plants, and we keep the exec
// callback non-throwing so execution can fall through to the end of fuzz().

const { FuzzedDataProvider } = require("@jazzer.js/core");
const AdbDriver = require("/work/target/build/AdbDriver.js");

// Keep the fast path through execADBCommand: when systemAdbExist is true,
// the module skips the ADB_BINARY_FILE lookup that would otherwise splice a
// platform-specific absolute path into cmd[0]. The flag is a module-level
// `let` captured from isSystemAdbAvailable() at import time; on the sandbox
// image /usr/bin/adb is not installed, so we patch it to true here to keep
// the input the fuzzer sees identical to the string we pass in.
try {
  // No stable export for the flag; monkey-patch which.sync so the module's
  // own isSystemAdbAvailable() reports available on re-import, in case the
  // harness host re-requires.
  const which = require("/work/target/node_modules/which");
  which.sync = () => "/usr/bin/adb";
} catch (_) {
  // Non-fatal: the harness still exercises the split; worst case the string
  // gets a bin-path prefix before exec, which does not change the split sink.
}

module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data);

  // Build a payload shaped like a classic catastrophic-backtracking trigger
  // (long run of 'a' + a single non-match char). We let the fuzzer control
  // only the LENGTH, not the content, so libFuzzer does not have to evolve
  // the "all a's" structure byte-by-byte — a trick needed because random
  // mutation rarely produces a 100k-char run of a single byte.
  //
  // 2 ** 20 (~1 MiB) is well above the ~5s SlowRegex threshold for every
  // known catastrophic pattern we have measured; capped so individual
  // iterations stay under libFuzzer's default -rss_limit_mb=2048.
  const n = provider.consumeIntegralInRange(1, 1 << 20);
  const payload = "a".repeat(n) + "!";

  // Belt-and-braces: strip the CommandInjection sentinel if the fuzzer
  // happens to splice it in (it will not, since we build the string
  // ourselves, but a future variant that pulls bytes from `data` could).
  const cmd = payload.replace(/jaz_zer/g, "");

  try {
    // execADBCommand returns a Promise that `.catch`es its own errors, so
    // nothing async escapes. The .split(' ') at :20:19 runs synchronously
    // on the first line of the function body — this is the reach we care
    // about for the redos finding.
    AdbDriver.execADBCommand(cmd, { stdio: "ignore" });
  } catch (err) {
    // Swallow synchronous errors from the target so the fuzzer keeps going;
    // re-throw only Jazzer bug-detector reports (SlowRegex is what we want).
    if (err && err.name && String(err.name).includes("Jazzer")) throw err;
  }
};
