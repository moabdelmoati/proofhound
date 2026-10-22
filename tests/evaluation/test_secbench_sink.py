from proofhound.evaluation.secbench import _resolve_sink


def test_bare_filename_resolves_to_the_unique_match(tmp_path):
    (tmp_path / "packages" / "bignumber" / "src.ts").mkdir(parents=True)
    (tmp_path / "packages" / "bignumber" / "src.ts" / "fixednumber.js").write_text("x")
    assert _resolve_sink("fixednumber.js:97:36", tmp_path) == "packages/bignumber/src.ts/fixednumber.js:97:36"


def test_ambiguous_basename_is_left_alone(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "util.js").write_text("x")
    (tmp_path / "b" / "util.js").write_text("x")
    assert _resolve_sink("util.js:1:1", tmp_path) == "util.js:1:1"


def test_existing_top_level_file_is_untouched(tmp_path):
    (tmp_path / "index.js").write_text("x")
    assert _resolve_sink("index.js:5:1", tmp_path) == "index.js:5:1"


def test_sink_with_a_directory_is_untouched(tmp_path):
    assert _resolve_sink("lib/x.js:1:1", tmp_path) == "lib/x.js:1:1"


def test_node_modules_matches_are_ignored(tmp_path):
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "util.js").write_text("x")
    assert _resolve_sink("util.js:1:1", tmp_path) == "util.js:1:1"


def test_empty_sink_is_passed_through(tmp_path):
    assert _resolve_sink("", tmp_path) == ""
