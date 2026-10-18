"""The one prompt format shared by training and serving the local harness model.

training/train/train_local.py and training/serve/serve_local.py both render [system, user] with
the tokenizer's chat template and the same system prompt the HarnessAgent sends, and fit
over-long prompts the same way, so the model is served exactly the kind of input it was trained
on. The assistant turn ends with <|im_end|>, which is also the stop token at generation time.
"""

import re

from proofhound.core.harness.agent import SYSTEM_PROMPT as SYSTEM

END_OF_TURN = "<|im_end|>"
METADATA_FILE = "proofhound_format.json"

# Qwen's ChatML, for base checkpoints whose tokenizer ships without a chat template.
_CHATML = (
    "{% for message in messages %}{{ '<|im_start|>' + message['role'] + '\n' + message['content']"
    " + '<|im_end|>' + '\n' }}{% endfor %}{% if add_generation_prompt %}"
    "{{ '<|im_start|>assistant\n' }}{% endif %}"
)

# Code blocks in HarnessAgent._prompt, shrunk in this order when a prompt is too long.
_SHRINKABLE = (
    re.compile(r"(Full module source[^\n]*\n```javascript\n)(.*?)(\n```)", re.DOTALL),
    re.compile(r"(Function source[^\n]*\n```javascript\n)(.*?)(\n```)", re.DOTALL),
)


def ensure_chat_template(tokenizer) -> None:
    if not tokenizer.chat_template:
        tokenizer.chat_template = _CHATML


def stop_token_ids(tokenizer) -> list[int]:
    ids = {tokenizer.convert_tokens_to_ids(END_OF_TURN)}
    if tokenizer.eos_token_id is not None:
        ids.add(tokenizer.eos_token_id)
    return sorted(i for i in ids if i is not None and i != tokenizer.unk_token_id)


def count_tokens(tokenizer, text: str) -> int:
    return len(tokenizer(text, add_special_tokens=False).input_ids)


def _keep_head_tail(body: str, keep: int) -> str:
    lines = body.splitlines()
    if keep >= len(lines):
        return body
    head, tail = keep - keep // 2, keep // 2
    omitted = len(lines) - keep
    kept_tail = lines[len(lines) - tail:] if tail else []
    return "\n".join([*lines[:head], f"// ... {omitted} lines omitted ...", *kept_tail])


def fit_user_prompt(tokenizer, text: str, max_tokens: int) -> str:
    """Shrink the module/function source blocks (keeping their head and tail) until it fits."""
    if count_tokens(tokenizer, text) <= max_tokens:
        return text
    for pattern in _SHRINKABLE:
        match = pattern.search(text)
        if not match:
            continue
        lines = match.group(2).count("\n") + 1
        keep = lines
        while keep > 0:
            keep = int(keep * 0.7)
            body = _keep_head_tail(match.group(2), keep)
            candidate = text[:match.start(2)] + body + text[match.end(2):]
            if count_tokens(tokenizer, candidate) <= max_tokens:
                return candidate
        text = candidate
    ids = tokenizer(text, add_special_tokens=False).input_ids
    if len(ids) <= max_tokens:
        return text
    half = max_tokens // 2
    return (
        tokenizer.decode(ids[:half]) + "\n// ... prompt truncated ...\n"
        + tokenizer.decode(ids[len(ids) - (max_tokens - half) + 16:])
    )


def render_prompt(tokenizer, messages: list[dict], max_prompt_tokens: int) -> str:
    """Chat-template the request, fitting the last user message into the token budget."""
    ensure_chat_template(tokenizer)
    if not messages or messages[0]["role"] != "system":
        messages = [{"role": "system", "content": SYSTEM}, *messages]
    user_index = max(i for i, m in enumerate(messages) if m["role"] == "user")
    empty = [*messages[:user_index], {"role": "user", "content": ""}, *messages[user_index + 1:]]
    overhead = count_tokens(
        tokenizer, tokenizer.apply_chat_template(empty, tokenize=False, add_generation_prompt=True)
    )
    fitted = fit_user_prompt(
        tokenizer, messages[user_index]["content"], max(64, max_prompt_tokens - overhead)
    )
    final = [*messages[:user_index], {"role": "user", "content": fitted}, *messages[user_index + 1:]]
    return tokenizer.apply_chat_template(final, tokenize=False, add_generation_prompt=True)
