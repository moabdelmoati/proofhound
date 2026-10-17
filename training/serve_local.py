"""Serve the fine-tuned Harness model locally behind an OpenAI-compatible endpoint.

Loads the base code model plus our trained LoRA adapter and exposes POST /v1/chat/completions
and GET /v1/models, so ProofHound's `openai_compatible` client can use it with no API, no data
leaving the machine. This is the runtime side of the privacy claim (RQ6).

    python training/serve_local.py --adapter models/harness-adapter --device cuda --port 8000
    # 3B adapters on a 6 GB GPU: add --load-4bit

Prompts are rendered with harness_format, exactly as train_local.py rendered them, and generation
stops at the end-of-turn token the model was trained to emit. The output is returned unmodified.
Uses only the Python stdlib HTTP server (no extra web dependency).
"""

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import harness_format as fmt

_STATE: dict = {}
DEFAULT_PROMPT_BUDGET = 1536


def _load(adapter: str, base: str | None, device: str, load_4bit: bool):
    import torch
    from peft import PeftConfig, PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    meta_path = Path(adapter) / fmt.METADATA_FILE
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    base = base or PeftConfig.from_pretrained(adapter).base_model_name_or_path
    print(f"loading base {base} + adapter {adapter} on {device} ...", flush=True)
    if not meta:
        print(f"WARNING: {meta_path} missing — adapter predates the shared format; "
              "outputs will not match training.", flush=True)
    tok = AutoTokenizer.from_pretrained(adapter)
    fmt.ensure_chat_template(tok)
    kwargs: dict = {"dtype": torch.float16 if device == "cuda" else torch.float32}
    if load_4bit:
        from transformers import BitsAndBytesConfig

        kwargs = {
            "quantization_config": BitsAndBytesConfig(
                load_in_4bit=True, bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.float16, bnb_4bit_use_double_quant=True,
            ),
            "device_map": {"": 0},
        }
    model = AutoModelForCausalLM.from_pretrained(base, **kwargs)
    model = PeftModel.from_pretrained(model, adapter)
    if not load_4bit:
        model.to(device)
    model.eval()
    _STATE.update(
        tok=tok, model=model, name="harness",
        prompt_budget=meta.get("prompt_budget", DEFAULT_PROMPT_BUDGET),
        stop_ids=fmt.stop_token_ids(tok),
    )
    print(f"model ready (prompt budget {_STATE['prompt_budget']} tokens)", flush=True)


def _generate(messages: list[dict], max_tokens: int, temperature: float) -> tuple[str, int, int, str]:
    import torch

    tok, model = _STATE["tok"], _STATE["model"]
    prompt = fmt.render_prompt(tok, messages, _STATE["prompt_budget"])
    inputs = tok(prompt, return_tensors="pt", add_special_tokens=False).to(model.device)
    sampling = {"do_sample": True, "temperature": temperature} if temperature > 0 else {"do_sample": False}
    with torch.no_grad():
        out = model.generate(
            **inputs, max_new_tokens=max_tokens, eos_token_id=_STATE["stop_ids"],
            pad_token_id=tok.pad_token_id or tok.eos_token_id, **sampling,
        )
    new = out[0][inputs["input_ids"].shape[1]:]
    finished = len(new) > 0 and int(new[-1]) in _STATE["stop_ids"]
    text = tok.decode(new, skip_special_tokens=True)
    return text, inputs["input_ids"].shape[1], len(new), "stop" if finished else "length"


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.rstrip("/").endswith("/models"):
            self._send(200, {"object": "list", "data": [{"id": _STATE["name"], "object": "model"}]})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self.path.rstrip("/").endswith("/chat/completions"):
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(length) or b"{}")
        text, prompt_tokens, completion_tokens, finish = _generate(
            req.get("messages", []),
            req.get("max_completion_tokens") or req.get("max_tokens") or 1536,
            req.get("temperature") or 0.0,
        )
        self._send(200, {
            "id": "local-1", "object": "chat.completion", "created": int(time.time()),
            "model": _STATE["name"],
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                         "finish_reason": finish}],
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                      "total_tokens": prompt_tokens + completion_tokens},
        })

    def log_message(self, *args):  # quiet
        pass


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", default="models/harness-adapter")
    ap.add_argument("--base", default=None)
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--device", default="cpu", choices=["cpu", "cuda"])
    ap.add_argument("--load-4bit", action="store_true", help="4-bit weights (needs bitsandbytes + CUDA).")
    args = ap.parse_args()
    _load(args.adapter, args.base, args.device, args.load_4bit)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"serving OpenAI-compatible endpoint at http://127.0.0.1:{args.port}/v1", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
