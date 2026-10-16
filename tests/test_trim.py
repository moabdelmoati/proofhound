"""Trim-harness logic used by the local server. Keeps one harness; cuts FIM leakage/repetition."""
from training.serve_local import _trim

HARNESS = (
    "const { FuzzedDataProvider } = require('@jazzer.js/core');\n"
    "const { exists } = require('./index.js');\n\n"
    "module.exports.fuzz = function(data) {\n"
    "    const provider = new FuzzedDataProvider(data);\n"
    "    exists(provider.consumeRemainingAsString(1024));\n"
    "};"
)


def test_trim_passes_a_clean_harness_unchanged():
    assert _trim(HARNESS) == HARNESS


def test_trim_cuts_repeated_second_copy_after_fim_marker():
    noisy = HARNESS + "\n<|fim_middle|>" + HARNESS
    assert _trim(noisy) == HARNESS


def test_trim_cuts_naive_repetition_after_closing_brace():
    noisy = HARNESS + "\n" + HARNESS
    assert _trim(noisy) == HARNESS


def test_trim_handles_nested_braces_inside_fuzz():
    nested = (
        "module.exports.fuzz = function(data) {\n"
        "    try { foo({a:1}); } catch (e) { if (e.name) {} }\n"
        "};\nmodule.exports.fuzz = function(x) { throw 1 }"
    )
    out = _trim(nested)
    assert out.count("module.exports.fuzz") == 1
    assert out.endswith("};")


def test_trim_without_marker_returns_stripped_input():
    assert _trim("  nothing to trim  ") == "nothing to trim"
