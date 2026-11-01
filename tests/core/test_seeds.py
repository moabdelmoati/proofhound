from pathlib import Path
import tempfile
from proofhound.core.fuzzing.seeds import seed_corpus, get_seed_file


def test_get_seed_file():
    assert get_seed_file("command-injection") is not None
    assert get_seed_file("cmd-injection") is not None
    assert get_seed_file("path-traversal") is not None
    assert get_seed_file("prototype-pollution") is not None
    assert get_seed_file("redos") is not None
    assert get_seed_file("unknown-class") is None


def test_seed_corpus():
    with tempfile.TemporaryDirectory() as tmp:
        corpus = Path(tmp) / "corpus"
        count = seed_corpus(corpus, "command-injection")
        assert count > 0
        files = list(corpus.glob("*"))
        assert len(files) == count
        # Check that seed content was written
        assert any(f.read_text(encoding="utf-8") == "jaz_zer" for f in files)
