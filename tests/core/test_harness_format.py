"""The shared train/serve prompt format: chat rendering and prompt shrinking."""

from types import SimpleNamespace

from proofhound.core.harness import chat_format as fmt


class WordTokenizer:
    """One token per whitespace-separated word; ChatML-like template."""

    chat_template = "fake"
    eos_token_id = 1
    unk_token_id = 0

    def __call__(self, text, add_special_tokens=False):
        return SimpleNamespace(input_ids=list(range(len(text.split()))))

    def decode(self, ids):
        return " ".join("w" for _ in ids)

    def convert_tokens_to_ids(self, token):
        return 2 if token == fmt.END_OF_TURN else 0

    def apply_chat_template(self, messages, tokenize=False, add_generation_prompt=False):
        body = "".join(f"<{m['role']}> {m['content']} </{m['role']}> " for m in messages)
        return body + ("<assistant> " if add_generation_prompt else "")


def _prompt(module_lines: int) -> str:
    module = "\n".join(f"line{i} x" for i in range(module_lines))
    return (
        "Generate a harness.\nFunction source (line 1 onward):\n```javascript\nfunction f(a) {}\n```\n"
        f"Full module source, for understanding imports and exports:\n```javascript\n{module}\n```\n"
        "Harness template to complete:\n```javascript\nmodule.exports.fuzz = function (data) {};\n```"
    )


def test_short_prompt_is_unchanged():
    tok = WordTokenizer()
    text = _prompt(5)
    assert fmt.fit_user_prompt(tok, text, 1000) == text


def test_long_module_source_is_shrunk_keeping_head_tail_and_template():
    tok = WordTokenizer()
    fitted = fmt.fit_user_prompt(tok, _prompt(500), 200)
    assert fmt.count_tokens(tok, fitted) <= 200
    assert "line0 x" in fitted and "line499 x" in fitted
    assert "lines omitted" in fitted
    assert "module.exports.fuzz = function (data) {};" in fitted
    assert "function f(a) {}" in fitted


def test_render_adds_pipeline_system_prompt_and_generation_turn():
    tok = WordTokenizer()
    rendered = fmt.render_prompt(tok, [{"role": "user", "content": _prompt(5)}], 1000)
    assert rendered.startswith("<system> " + fmt.SYSTEM)
    assert rendered.endswith("<assistant> ")


def test_render_fits_whole_prompt_into_budget():
    tok = WordTokenizer()
    messages = [{"role": "system", "content": fmt.SYSTEM}, {"role": "user", "content": _prompt(800)}]
    rendered = fmt.render_prompt(tok, messages, 300)
    assert fmt.count_tokens(tok, rendered) <= 300


def test_stop_tokens_include_end_of_turn_and_eos():
    assert fmt.stop_token_ids(WordTokenizer()) == [1, 2]
