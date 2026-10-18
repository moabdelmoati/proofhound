from pathlib import Path

from proofhound.core.adapters.base import innermost
from proofhound.core.adapters.javascript import (
    JavaScriptAdapter,
    first_target_frame,
    parse_jazzer_output,
)
from proofhound.core.analysis.semgrep import to_finding

SOURCE = b"""\
class A {
  ping(x) { return 1 }
}
module.exports.foo = function (a) {
  const inner = () => a;
  return inner();
};
exports.bar = (b) => b;
"""

JAZZER_OUTPUT = """\
#843	REDUCE cov: 12 ft: 12 corp: 4/4b lim: 8 exec/s: 210 rss: 149Mb L: 1/1 MS: 1 ShuffleBytes-
==1== Command Injection
    in execSync(): called with 'command -v jaz_zerp 2>/dev/null'
    at commandExistsUnixSync (/work/target/lib/command-exists.js:78:22)
    at Function.sync (/work/target/lib/command-exists.js:124:12)
    at module.exports.fuzz (/work/out/harness.js:8:19)
MS: 4 ChangeBinInt-ChangeBit-ChangeBit-CMP- DE: "jaz_zer"-;
artifact_prefix='/work/out/'; Test unit written to /work/out/crash-7ecae466
"""


def test_function_names_and_ranges():
    fns = JavaScriptAdapter().functions(Path("x.js"), SOURCE)
    assert [(f.name, f.start_line, f.end_line) for f in fns] == [
        ("A.ping", 2, 2),
        ("module.exports.foo", 4, 7),
        ("inner", 5, 5),
        ("exports.bar", 8, 8),
    ]


def test_innermost_prefers_smallest_named_function():
    fns = JavaScriptAdapter().functions(Path("x.js"), SOURCE)
    assert innermost(fns, 5).name == "inner"
    assert innermost(fns, 6).name == "module.exports.foo"
    assert innermost(fns, 1) is None


def test_parse_jazzer_command_injection():
    [report] = parse_jazzer_output(JAZZER_OUTPUT)
    assert report.kind == "Command Injection"
    assert report.is_vulnerability
    assert report.crash_file == "crash-7ecae466"
    assert first_target_frame(report.frames) == "lib/command-exists.js:78:22"


def test_parse_uncaught_exception_is_not_a_vulnerability():
    [report] = parse_jazzer_output("==7== Uncaught Exception: TypeError: x is not a function\n")
    assert report.kind == "Uncaught Exception"
    assert not report.is_vulnerability


def test_semgrep_result_to_finding():
    finding = to_finding({
        "check_id": "rules.proofhound.js.command-injection",
        "path": "lib/command-exists.js",
        "start": {"line": 78, "col": 31},
        "extra": {
            "message": "[source: commandName] [sink: 'command -v ' +\n  commandName] Data reaches a shell.",
            "severity": "ERROR",
            "metadata": {"vuln_class": "command-injection"},
        },
    })
    assert finding.rule_id == "proofhound.js.command-injection"
    assert finding.source == "commandName"
    assert finding.sink == "'command -v ' + commandName"
    assert finding.message == "Data reaches a shell."
    assert finding.vuln_class == "command-injection"


def test_python_adapter_extracts_qualified_names():
    from proofhound.core.adapters.python import PythonAdapter

    src = b"def handler(req, path):\n    return path\n\nclass A:\n    def m(self, x):\n        return x\n"
    fns = PythonAdapter().functions(Path("x.py"), src)
    assert [(f.name, f.start_line) for f in fns] == [("handler", 1), ("A.m", 5)]


def test_adapter_registry():
    from proofhound.core.adapters import get_adapter

    assert get_adapter("javascript").name == "javascript"
    assert get_adapter("python").name == "python"
