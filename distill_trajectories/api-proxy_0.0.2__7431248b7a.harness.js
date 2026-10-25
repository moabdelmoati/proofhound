// Jazzer.js harness for api-proxy@0.0.2 path-traversal at lib/static.js:40:9.
//
// The v4 eval tagged finding 7431248b7a on this case as the ReDoS class, but
// the sink line is `FS.readFile(filepath, 'binary', ...)` and the vulnerable
// surface is a path-traversal, not a slow regex: the module strips only the
// query/hash from `request.url` and joins the rest directly against the
// static root.  We confirm the real class with Jazzer.js's PathTraversal
// detector, which is what the fuzzer trips here.
//
// Call chain:
//   exports.writeStatic(request, response, callback)              // lib/static.js:3
//     -> url = request.url.replace(/[?#][\s\S]*/, '')              // strip query/hash
//     -> filepath = Path.join(root, url)                           // root = <pkg>/www
//          ^^ detector fires inside node:path's normalize() for the sentinel
//     -> FS.stat(filepath, cb)
//          -> writeFile(request, response, filepath)
//             -> FS.readFile(filepath, 'binary', ...)              // sink at line 40:9
//
// Path.join leaves `../` segments at the start of the URL in the resolved
// path, so a request URL that begins with `../../..` escapes `www/`.  The
// Jazzer.js PathTraversal detector plants its sentinel ("../jaz_zer")
// through libFuzzer compare interception and flags any fs-adjacent path
// operation whose argument contains it; path.normalize is hooked, so the
// detector fires inside Path.join before the asynchronous readFile at
// line 40 runs.

const { FuzzedDataProvider } = require("@jazzer.js/core");
const { writeStatic } = require("/work/target/lib/static.js");

function fakeResponse() {
  return {
    writeHead() {},
    write() {},
    end() {},
    on() {},
  };
}

module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data);
  // Full fuzzer control over the request URL.  NUL bytes make Path.join
  // throw a TypeError in Node >= 10 and would short-circuit the fuzz run
  // before libFuzzer evolves the detector sentinel, so we strip them.
  const url = provider.consumeRemainingAsString().replace(/\u0000/g, "");

  const request = { url };
  const response = fakeResponse();

  try {
    writeStatic(request, response, function noopCallback() {});
  } catch (err) {
    // Re-throw Jazzer bug-detector reports; swallow only target-domain
    // errors so the fuzzer keeps evolving inputs toward the sentinel.
    if (err && err.name && String(err.name).includes("Jazzer")) throw err;
    if (err && typeof err.message === "string"
        && /path traversal|command injection|prototype pollution/i.test(err.message)) {
      throw err;
    }
  }
};
