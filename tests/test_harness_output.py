"""Extracting the harness code from a model reply."""

from proofhound.agents.harness import _javascript

HARNESS = (
    'const { FuzzedDataProvider } = require("@jazzer.js/core");\n'
    "module.exports.fuzz = function (data) {\n  target(data.toString());\n};"
)


def test_plain_code_is_kept():
    assert _javascript(HARNESS) == HARNESS + "\n"


def test_fenced_code_is_unwrapped():
    assert _javascript(f"```javascript\n{HARNESS}\n```") == HARNESS + "\n"


def test_prose_around_the_fence_is_dropped():
    reply = f"Here is the harness:\n\n```js\n{HARNESS}\n```\nIt fuzzes the target."
    assert _javascript(reply) == HARNESS + "\n"


def test_block_with_fuzz_entry_point_wins_over_earlier_blocks():
    reply = f"The function:\n```javascript\nfunction target(x) {{}}\n```\nHarness:\n```javascript\n{HARNESS}\n```"
    assert _javascript(reply) == HARNESS + "\n"


def test_unterminated_fence_keeps_the_code():
    assert _javascript(f"```javascript\n{HARNESS}") == HARNESS + "\n"
