from proofhound.core.harness.check import summarize_failure

PROBE_LOG = """INFO: Using generated seed: 902083802
(node:1) Warning: Accessing non-existent property 'default' of module exports inside circular dependency
(Use `node --trace-warnings ...` to show where the warning was created)
Error: EROFS: read-only file system, chmod '/work/target/bin/linux/aapt'
    at Object.chmodSync (node:fs:1983:11)
    at Object.<anonymous> (/work/target/index.js:7:16)
    at Object.<anonymous> (/work/out/harness.js:2:16)
    at Module._compile (/opt/jazzer/node_modules/source-map-support/source-map-support.js:568:25)
    at loadFuzzFunction (/opt/jazzer/node_modules/@jazzer.js/core/core.ts:345:21)"""


def test_summary_keeps_the_error_and_target_frames_only():
    summary = summarize_failure(PROBE_LOG)
    assert summary.splitlines() == [
        "Error: EROFS: read-only file system, chmod '/work/target/bin/linux/aapt'",
        "    at Object.chmodSync (node:fs:1983:11)",
        "    at Object.<anonymous> (/work/target/index.js:7:16)",
        "    at Object.<anonymous> (/work/out/harness.js:2:16)",
    ]


def test_long_output_is_cut_keeping_head_and_tail():
    output = "Error: first\n" + "noise line from the target\n" * 2000 + "TypeError: last"
    summary = summarize_failure(output, limit=500)
    assert len(summary) < 600
    assert summary.startswith("Error: first") and summary.endswith("TypeError: last")
    assert "characters omitted" in summary
