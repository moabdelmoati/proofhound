// Jazzer.js harness for api-proxy@0.0.2 path-traversal at lib/static.js:40:9.
//
// Call chain:
//   static.writeStatic(request, response, callback)
//     var root = Path.resolve(require.resolve('api-proxy/lib/static.js'), '../../www')
//     var url  = request.url.replace(/[?#][\s\S]*/, '')
//     var filepath = Path.join(root, url)        // sentinel-bearing arg flows into path.normalize
//       -> FS.stat(filepath, cb)                 // hooked, but normalized -> no sentinel
//            -> writeFile(req, res, filepath)
//                 -> FS.readFile(filepath, 'binary', ...)  // sink @ lib/static.js:40:9
//
// Jazzer.js's PathTraversal detector hooks fs.* AND path.normalize/resolve, so the
// unnormalized `root + '/' + url` passed into path.join -> path.normalize fires the
// detector as soon as libFuzzer places the sentinel '../../jaz_zer' into url.
// (Normalization erases `..`, so by the time fs.readFile sees `filepath` the
// sentinel is gone -- the path-module hook is what actually fires on this bug.)
//
// static.js uses `require.resolve('api-proxy/lib/static.js')` internally. We're
// loading the package by absolute path (not via node_modules), so we monkey-patch
// Module._resolveFilename to answer that lookup instead of installing a symlink
// into a read-only target mount.

const Module = require("module");
const origResolve = Module._resolveFilename.bind(Module);
Module._resolveFilename = function (req, parent, ...rest) {
  if (typeof req === "string" && req.startsWith("api-proxy/")) {
    return require("path").join("/work/target", req.slice("api-proxy/".length));
  }
  return origResolve(req, parent, ...rest);
};

const { FuzzedDataProvider } = require("@jazzer.js/core");
const staticMod = require("/work/target/lib/static.js");

function makeResponse() {
  return {
    writeHead: () => {},
    write: () => {},
    end: () => {},
  };
}

module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data);
  // Full fuzzer control over the URL. Jazzer.js's PathTraversal detector adds
  // '../../jaz_zer' to libFuzzer's dictionary via guideTowardsContainment, so
  // this string flows straight into path.normalize via path.join(root, url).
  // Null bytes are stripped so Node's own path/fs validators don't short-circuit
  // the harness with the wrong error class before the detector hook runs.
  const url = provider.consumeRemainingAsString().replace(/\u0000/g, "");

  const request = { url };
  const response = makeResponse();
  const callback = () => {}; // writeStatic invokes this when stat says "not found"

  try {
    staticMod.writeStatic(request, response, callback);
  } catch (err) {
    // Re-throw Jazzer bug-detector findings; swallow target-domain errors
    // (TypeError on bad url shapes, ERR_INVALID_ARG_TYPE, etc.) so the fuzzer
    // keeps evolving the input toward the sentinel.
    if (err && err.name && String(err.name).includes("Jazzer")) throw err;
    if (err && typeof err.message === "string"
        && /path traversal|command injection|prototype pollution/i.test(err.message)) {
      throw err;
    }
  }
};
