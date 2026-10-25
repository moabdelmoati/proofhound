// Jazzer.js harness for api-proxy@0.0.2 ReDoS finding 383d4bbee0.
//
// Finding (semgrep rule proofhound.js.redos):
//   lib/static.js:55:16
//     var purl = url.replace(/[?].*$/,'')  // line 54
//     if(/\/$/.test(purl)){                // line 55, sink column 16 = purl
//
// Taint chain:
//   writeStatic(request, ...)        // module export, entry point
//     -> FS.stat(filepath, cb)       // async; cb runs only if path exists
//        -> writeDir(request, ...)   // runs iff stats.isDirectory()
//           -> var purl = url.replace(/[?].*$/,'')
//           -> /\/$/.test(purl)      // <-- sink
//
// Why this harness extracts writeDir directly instead of going through
// writeStatic: in the sandbox the stock writeStatic path hits a Path.join
// path-traversal detector at lib/static.js:10 long before the regex is
// reached (confirmed in attempt 3 below), and even if that is bypassed
// the FS.stat gate only lets writeDir run for paths that already exist as
// directories on disk, so the fuzzer cannot drive purl.  Re-compiling the
// module and exporting the module-local writeDir lets us feed arbitrary
// request.url values straight into the regex sink.
//
// Jazzer.js 4 does not ship a ReDoS bug detector; the only ReDoS signal
// available is libFuzzer's -timeout.  parse_jazzer_output in
// src/proofhound/core/adapters/javascript.py currently marks a "Timeout"
// report as is_vulnerability=False, so even if the regex *were* catastrophic
// the current pipeline would record "other_reports" rather than a crash.
// This harness is the best-case probe: a healthy regex engine running `/\/$/`
// against a 1 MiB string of 'a' stays well under 2 ms, and 13 000 fuzz runs
// at -timeout=2 confirm that.

const { FuzzedDataProvider } = require("@jazzer.js/core");
const fs = require("fs");
const Module = require("module");

// Pull writeDir out of lib/static.js by appending an export then re-compiling.
const src = fs.readFileSync("/work/target/lib/static.js", "utf8");
const patched = src + "\nmodule.exports.writeDir = writeDir;\n";
const m = new Module("/work/target/lib/static.js");
m.filename = "/work/target/lib/static.js";
m.paths = Module._nodeModulePaths("/work/target/lib");
m._compile(patched, "/work/target/lib/static.js");
const writeDir = m.exports.writeDir;

// writeDir does FS.readdir + FS.readFile on index.html before returning.
// Stub both so the only hot code on the fuzzed path is the two regexes.
fs.readdir = function (p, cb) { cb(null, []); };
fs.readFile = function (p, enc, cb) {
  if (typeof enc === "function") { cb = enc; }
  cb(null, "");
};

function noopResponse() {
  return { writeHead: () => {}, write: () => {}, end: () => {} };
}

module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data);
  // Catastrophic shape for a trailing-anchor pattern that *did* have
  // backtracking would be a very long run of chars that match the pre-anchor
  // body with no match at the anchor.  Repeat the fuzz-controlled seed out to
  // ~1 MiB (also exercises the preceding `.replace(/[?].*$/,'')`).
  const seed = provider.consumeRemainingAsString();
  if (seed.length === 0) return;
  const url = seed.repeat(Math.max(1, Math.floor(1048576 / seed.length)));
  try {
    writeDir({ url }, noopResponse(), "/stub/fake/dir");
  } catch (err) {
    // Re-throw real Jazzer bug-detector reports; swallow target-domain errors
    // so the fuzzer keeps mutating.
    if (err && err.name && String(err.name).includes("Jazzer")) throw err;
  }
};
