// Jazzer.js harness for aaptjs@1.3.1 command-injection at index.js:18:3.
//
// Call chain:
//   require("/work/target/index.js").list(apkfilePath, cb)
//     -> promistify(`${aapt} l ${apkfilePath}`, cb)
//        -> exec(cmd, cb)                                 // sink: index.js:18:3
//
// The user-controlled `apkfilePath` is interpolated straight into the shell
// template `${aapt} l ${apkfilePath}` with no escaping, so Jazzer.js's
// CommandInjection detector fires as soon as libFuzzer plants its "jaz_zer"
// sentinel into the string.
//
// Module-load workarounds (why the 7B harness could not even require the
// module in the sandbox):
//   1. aaptjs starts with `require('shelljs/global')`. Loading shelljs core
//      adds `.to`/`.toEnd` on String.prototype -- that trips Jazzer.js's
//      Prototype Pollution bug-detector at require time, which fires BEFORE
//      the fuzz loop ever runs (an unrelated detector, not our sink). We
//      therefore pre-cache `shelljs/global` to an empty stub module and
//      install `global.exec = child_process.exec` by hand, so index.js's
//      `exec(cmd, cb)` call resolves to the native child_process.exec that
//      Jazzer's CommandInjection detector hooks.
//   2. aaptjs then runs `fs.chmodSync(bin/<platform>/aapt, '777')` at
//      require time (lines 10-13). /work/target is bind-mounted read-only
//      in the sandbox, so chmodSync throws EROFS before module.exports is
//      set and `require` throws before the harness calls into it. We stub
//      fs.chmodSync BEFORE the require.

const Module = require("module");
const path = require("path");
const child_process = require("child_process");

// (1) Make `require('shelljs/global')` a no-op by pre-populating the
// require cache with a stub module at the id Node will resolve to. We
// resolve from the target directory so the id matches what index.js sees.
const shellGlobalId = require.resolve("shelljs/global", {
  paths: ["/work/target", "/work/target/node_modules"],
});
require.cache[shellGlobalId] = {
  id: shellGlobalId,
  filename: shellGlobalId,
  loaded: true,
  exports: {},
  children: [],
  paths: Module._nodeModulePaths(path.dirname(shellGlobalId)),
};
// shelljs/global's documented side effect is to publish each shelljs command
// (including `exec`) as a global. We only need `exec`, and we want it to be
// the native child_process.exec so Jazzer's CommandInjection detector hooks
// the call.
global.exec = child_process.exec;

// (2) Defeat the EROFS at require time (index.js line 12).
const fs = require("fs");
fs.chmodSync = function () {};

const { FuzzedDataProvider } = require("@jazzer.js/core");
const aaptjs = require("/work/target/index.js");

module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data);
  // Full fuzzer control over the shell-injected substring. Node's
  // child_process.exec rejects strings containing NUL bytes with a
  // TypeError that is NOT the bug we are after, so strip NULs to keep the
  // detector sentinel evolving.
  const apkfilePath = provider.consumeRemainingAsString().replace(/\u0000/g, "");

  let p;
  try {
    // list() builds `${aapt} l ${apkfilePath}` and hands it to exec().
    // Jazzer's child_process.exec hook inspects the command string before
    // the shell runs, so the detector fires on the first iteration whose
    // apkfilePath contains "jaz_zer" even though exec is async.
    p = aaptjs.list(apkfilePath, function () {});
  } catch (err) {
    if (err && err.name && String(err.name).includes("Jazzer")) throw err;
    return;
  }
  // Swallow the async rejection (aapt will exit non-zero or not exist on
  // PATH); that is unrelated to the CommandInjection detector.
  if (p && typeof p.catch === "function") {
    p.catch(function () {});
  }
};
