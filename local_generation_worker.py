"""One-shot local model worker; stdin is its complete generation context."""

import base64
import json
import os
import socket
import sys


MAX_REQUEST_BYTES = 32_768
MODEL_PATH = "/model/model.gguf"


def parse_context(raw: bytes) -> str:
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("generation context exceeds worker limit")
    request = json.loads(raw)
    if type(request) is not dict or set(request) != {"inputs"}:
        raise ValueError("worker accepts only sealed inputs")
    if type(request["inputs"]) is not list or not request["inputs"]:
        raise ValueError("sealed inputs required")

    parts = []
    for source in request["inputs"]:
        if type(source) is not dict or set(source) != {"media_type", "content_base64"}:
            raise ValueError("worker input contains unmediated context")
        if source["media_type"] != "text/plain" or type(source["content_base64"]) is not str:
            raise ValueError("local worker accepts governed text only")
        payload = base64.b64decode(source["content_base64"], validate=True)
        parts.append(payload.decode("utf-8"))
    return "\n\n".join(parts)


def check_isolation() -> None:
    allowed_environment = {"PATH", "HOME", "PYTHONDONTWRITEBYTECODE",
                           "OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "LC_CTYPE"}
    if not set(os.environ) <= allowed_environment:
        raise RuntimeError("worker received unexpected environment")
    if any(os.path.exists(path) for path in ("/workspace", "/ipc", "/run/secrets")):
        raise RuntimeError("worker has a governed or secret mount")
    if not os.path.isfile(MODEL_PATH) or os.listdir("/model") != ["model.gguf"]:
        raise RuntimeError("worker model mount is not isolated")
    with open(MODEL_PATH, "rb") as model_file:
        if model_file.read(4) != b"GGUF":
            raise RuntimeError("worker model artifact is not GGUF")
    try:
        socket.create_connection(("198.51.100.1", 80), timeout=0.2)
    except OSError:
        pass
    else:
        raise RuntimeError("worker has an outbound route")


def main() -> None:
    check_isolation()
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    prompt = parse_context(raw)
    if not prompt.strip():
        raise ValueError("empty sealed context")

    from llama_cpp import Llama

    model = Llama(model_path=MODEL_PATH, n_ctx=512, n_threads=2, n_threads_batch=2,
                  n_gpu_layers=0, verbose=False)
    if len(model.tokenize(prompt.encode("utf-8"), add_bos=True)) > 480:
        raise ValueError("sealed context exceeds model window")
    result = model(prompt, max_tokens=32, temperature=0, echo=False)
    text = result["choices"][0]["text"].strip()
    if not text:
        raise RuntimeError("local model returned empty text")
    sys.stdout.write(json.dumps({"text": text}))


if __name__ == "__main__":
    main()
