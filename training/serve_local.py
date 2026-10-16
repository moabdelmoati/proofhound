"""Serve the fine-tuned Harness model locally behind an OpenAI-compatible endpoint.

Loads the base code model plus our trained LoRA adapter and exposes POST /v1/chat/completions
and GET /v1/models, so ProofHound's `openai_compatible` client can use it with no API, no data
leaving the machine. This is the runtime side of the privacy claim (RQ6).

    python training/serve_local.py --adapter models/harness-adapter --port 8000
    # then in configs/default.yaml set harness.model to a models: entry like:
    #   local-harness: {provider: openai_compatible, model: harness, base_url: http://localhost:8000/v1}

Uses only the Python stdlib HTTP server (no extra web dependency). CPU by default; pass --device
cuda to use the GPU. The base model downloads from Hugging Face on first run.
"""

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_STATE: dict = {}


def _load(adapter: str, base: str | None, device: str):
    import torch
    from peft import PeftConfig, PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    cfg = PeftConfig.from_pretrained(adapter)
    base = base or cfg.base_model_name_or_path
    print(f"loading base {base} + adapter {adapter} on {device} ...", flush=True)
    tok = AutoTokenizer.from_pretrained(adapter)
    dtype = torch.float16 if device == "cuda" else torch.float32
    model = AutoModelForCausalLM.from_pretrained(base, torch_dtype=dtype)
    model = PeftModel.from_pretrained(model, adapter)
    model.to(device).eval()
    _STATE.update(tok=tok, model=model, device=device, name="harness")
    print("model ready", flush=True)


def _generate(messages: list[dict], max_tokens: int, temperature: float) -> str:
    import torch

    tok, model, device = _STATE["tok"], _STATE["model"], _STATE["device"]
    prompt = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tok(prompt, return_tensors="pt").to(device)
    with torch.no_grad():
        out = model.generate(
            **inputs, max_new_tokens=max_tokens, do_sample=temperature > 0,
            temperature=max(temperature, 1e-5), pad_token_id=tok.eos_token_id,
        )
    return tok.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        if self.path.rstrip("/").endswith("/models"):
            self._send(200, {"object": "list", "data": [{"id": _STATE["name"], "object": "model"}]})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        if not self.path.rstrip("/").endswith("/chat/completions"):
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(length) or b"{}")
        text = _generate(
            req.get("messages", []),
            req.get("max_completion_tokens") or req.get("max_tokens") or 2048,
            req.get("temperature", 0.0),
        )
        self._send(200, {
            "id": "local-1", "object": "chat.completion", "created": int(time.time()),
            "model": _STATE["name"],
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        })

    def log_message(self, *args):  # quiet
        pass


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", default="models/harness-adapter")
    ap.add_argument("--base", default=None)
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--device", default="cpu", choices=["cpu", "cuda"])
    args = ap.parse_args()
    _load(args.adapter, args.base, args.device)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"serving OpenAI-compatible endpoint at http://127.0.0.1:{args.port}/v1", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
