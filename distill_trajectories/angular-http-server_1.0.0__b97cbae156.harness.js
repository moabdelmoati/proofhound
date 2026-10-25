// Jazzer.js harness for angular-http-server@1.0.0 path-traversal at angular-http-server.js:16:29.
//
// Target shape (angular-http-server.js is a shebang script with no exports):
//   var server = http.createServer(function (req, res) {
//     var possibleFilename = req.url.slice(1) || "dummy";
//     fs.stat(possibleFilename, function (err, stats) {    // detector fires here (fs.stat is hooked)
//       if (!err && stats.isFile()) {
//         fileBuffer = fs.readFileSync(possibleFilename);  // sink @ line 16:29
//       } else {
//         fileBuffer = fs.readFileSync("index.html");      // fallback: resolved against cwd
//       }
//     });
//   });
//   server.listen(8000, ...);
//
// Jazzer.js's path-traversal detector hooks the whole fs/path surface (see
// @jazzer.js/bug-detectors/dist/internal/path-traversal.js) and seeds the libFuzzer
// dictionary with the sentinel "../../jaz_zer". fs.stat is hooked, so when
// possibleFilename contains the sentinel the detector throws synchronously from the
// stat before-hook -- the async callback (and therefore line 16's readFileSync)
// never has to run. req.url.slice(1) just strips the leading byte, so
// req.url = "/../../jaz_zer" lines up the sentinel byte-for-byte.
//
// Two things make the module non-trivial to load:
//   1. It has no exports -- the request handler is passed anonymously to
//      http.createServer. We monkey-patch http.createServer before loading so we can
//      capture that handler and hand back a stub whose listen() is a no-op (binding
//      port 8000 would fail outright under --network none anyway).
//   2. The fallback branch does fs.readFileSync("index.html") with a bare filename,
//      resolved against process.cwd(). Jazzer starts the harness in /tmp, where no
//      index.html exists, so empty / non-matching inputs would throw ENOENT inside
//      the fs.stat callback and terminate the fuzz target before the seed runs.
//      We chdir to /work/target so the real index.html next to the module is served.

const path = require("path");
const TARGET_DIR = "/work/target";
process.chdir(TARGET_DIR);

const http = require("http");

let capturedHandler = null;
const origCreateServer = http.createServer.bind(http);
http.createServer = function (handler) {
  if (typeof handler === "function") {
    capturedHandler = handler;
  }
  return {
    listen: function () { return this; },
    on: function () { return this; },
    close: function (cb) { if (typeof cb === "function") cb(); return this; },
    address: function () { return { port: 0, family: "IPv4", address: "127.0.0.1" }; },
  };
};

// Load the target. Node ignores the shebang; the module body runs, registers the
// handler through our patched createServer, and calls the stub listen().
require(path.join(TARGET_DIR, "angular-http-server.js"));

const { FuzzedDataProvider } = require("@jazzer.js/core");

function makeResponse() {
  return { writeHead: () => {}, write: () => {}, end: () => {} };
}

module.exports.fuzz = function (data) {
  if (capturedHandler === null) return;
  const provider = new FuzzedDataProvider(data);
  // Full fuzzer control over the URL. consumeRemainingAsString + a leading "/" means
  // req.url.slice(1) is the fuzzer's bytes verbatim; the sentinel "../../jaz_zer"
  // flows straight into fs.stat and the detector before-hook fires on it.
  // Strip NULs so Node's own path validators do not short-circuit with
  // ERR_INVALID_ARG_VALUE before the detector hook runs.
  let url = provider.consumeRemainingAsString().replace(/\u0000/g, "");
  if (!url.startsWith("/")) url = "/" + url;

  const req = { url, method: "GET", headers: {} };
  const res = makeResponse();

  try {
    capturedHandler(req, res);
  } catch (err) {
    // Re-throw Jazzer bug-detector findings; swallow target-domain errors so the
    // fuzzer keeps evolving toward the sentinel.
    if (err && err.name && String(err.name).includes("Jazzer")) throw err;
    if (err && typeof err.message === "string"
        && /path traversal|command injection|prototype pollution/i.test(err.message)) {
      throw err;
    }
  }
};
