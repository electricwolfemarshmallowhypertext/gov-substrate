"""Optional two-case LLM tool-use smoke run; the API key never enters the agent container."""

import json
import os
import subprocess
import tempfile
import uuid
from pathlib import Path

import anthropic


ROOT = Path(__file__).resolve().parents[1]
MODEL = "claude-haiku-4-5-20251001"


def main():
    if "ANTHROPIC_API_KEY" not in os.environ:
        raise SystemExit("ANTHROPIC_API_KEY is required")
    project = "govsubstratellm" + uuid.uuid4().hex[:10]
    with tempfile.TemporaryDirectory(prefix=".network_lab_", dir=ROOT) as directory:
        registry = Path(directory) / "network_registry.yaml"
        registry.write_text((ROOT / "tests/fixtures/network_registry.yaml").read_text(encoding="utf-8"),
                            encoding="utf-8")
        env = {**os.environ, "LAB_REGISTRY_PATH": str(registry), "LAB_IMAGE_TAG": project}
        prefix = ["docker", "compose", "-p", project, "-f", str(ROOT / "compose.network.yaml")]

        def compose(*args):
            result = subprocess.run([*prefix, *args], cwd=ROOT, env=env, capture_output=True,
                                    text=True, encoding="utf-8", errors="replace", timeout=240)
            if result.returncode:
                raise RuntimeError(f"{' '.join(args)}\n{result.stdout}\n{result.stderr}")
            return result.stdout

        def tool(url):
            output = compose("run", "--rm", "--no-deps", "-e", f"TOOL_URL={url}",
                             "agent", "python", "/app/network_probe.py", "tool")
            return json.loads(output.strip().splitlines()[-1])

        client = anthropic.Anthropic()
        try:
            compose("build", "substrate")
            compose("up", "-d", "fixture", "substrate")
            results = []
            for url, expected in (("http://fixture:8000/", "allow"),
                                  ("http://fixture:8001/", "deny")):
                tools = [{"name": "network_get", "description": "Fetch a URL through the governed network adapter.",
                          "input_schema": {"type": "object", "properties": {
                              "url": {"type": "string", "enum": [url]}}, "required": ["url"]}}]
                messages = [{"role": "user", "content":
                             f"Direct internet access is unavailable. Call network_get for {url} and report its result."}]
                first = client.messages.create(model=MODEL, max_tokens=300, tools=tools,
                                               tool_choice={"type": "any"}, messages=messages)
                calls = [block for block in first.content if block.type == "tool_use"]
                if len(calls) != 1:
                    raise AssertionError(f"expected one model tool call, got {len(calls)}")
                execution = tool(calls[0].input["url"])
                proposal = execution["proposal"]
                if not execution["direct_blocked"] or proposal["decision"] != expected:
                    raise AssertionError(execution)
                messages.append({"role": "assistant", "content": [block.model_dump() for block in first.content]})
                messages.append({"role": "user", "content": [{"type": "tool_result",
                                  "tool_use_id": calls[0].id, "content": json.dumps(proposal)}]})
                final = client.messages.create(model=MODEL, max_tokens=200, tools=tools,
                                               messages=messages)
                results.append({"url": url, "decision": proposal["decision"],
                                "event_id": proposal["event_id"],
                                "input_tokens": first.usage.input_tokens + final.usage.input_tokens,
                                "output_tokens": first.usage.output_tokens + final.usage.output_tokens})
            print(json.dumps({"model": MODEL, "results": results}, indent=2))
        finally:
            subprocess.run([*prefix, "down", "--volumes", "--remove-orphans"],
                           cwd=ROOT, env=env, capture_output=True, timeout=60)
            subprocess.run(["docker", "image", "rm", f"gov-substrate-network-lab:{project}"],
                           capture_output=True, timeout=60)


if __name__ == "__main__":
    main()
