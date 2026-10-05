"""Verify the committed Phase 10 evidence ledger and its file hashes."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "evaluation" / "evidence-freeze-2026-10-05" / "manifest.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(require_tag: bool = False) -> dict[str, int]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    allowed_outcomes = set(manifest["outcome_vocabulary"])
    if allowed_outcomes != {"held", "detected", "denied", "outside_boundary"}:
        raise AssertionError("unexpected outcome vocabulary")

    artifacts = manifest["artifacts"]
    paths: set[str] = set()
    for artifact_id, artifact in artifacts.items():
        relative = artifact["path"]
        if relative in paths:
            raise AssertionError(f"duplicate artifact path: {relative}")
        paths.add(relative)
        path = ROOT / relative
        if not path.is_file():
            raise AssertionError(f"missing artifact {artifact_id}: {relative}")
        if sha256(path) != artifact["sha256"]:
            raise AssertionError(f"artifact hash mismatch: {artifact_id}")
        if path.suffix == ".json":
            json.loads(path.read_text(encoding="utf-8"))

    claim_ids: set[str] = set()
    for claim in manifest["claims"]:
        if claim["id"] in claim_ids:
            raise AssertionError(f"duplicate claim id: {claim['id']}")
        claim_ids.add(claim["id"])
        if claim["outcome"] not in allowed_outcomes:
            raise AssertionError(f"invalid outcome for {claim['id']}")
        if not claim["environment_artifacts"] or not claim["raw_results"]:
            raise AssertionError(f"claim lacks environment or raw result: {claim['id']}")
        for artifact_id in claim["environment_artifacts"] + claim["raw_results"]:
            if artifact_id not in artifacts:
                raise AssertionError(f"unknown artifact {artifact_id} in {claim['id']}")
        for relative in claim["implementation"] + claim["tests"]:
            if not (ROOT / relative).is_file():
                raise AssertionError(f"missing evidence path in {claim['id']}: {relative}")

    ci_result = json.loads((ROOT / artifacts["ci_run"]["path"]).read_text(encoding="utf-8"))
    if ci_result["headSha"] != manifest["tested_commit"] or ci_result["conclusion"] != "success":
        raise AssertionError("CI result does not match the tested commit and success state")

    if require_tag:
        tag = manifest["freeze_tag"]
        tag_commit = subprocess.check_output(
            ["git", "rev-parse", f"{tag}^{{commit}}"], cwd=ROOT, text=True).strip()
        head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        if tag_commit != head:
            raise AssertionError(f"{tag} does not point to HEAD")
        ancestor = subprocess.run(
            ["git", "merge-base", "--is-ancestor", manifest["tested_commit"], tag_commit],
            cwd=ROOT, check=False)
        if ancestor.returncode != 0:
            raise AssertionError("tested commit is not an ancestor of the freeze tag")

    return {"artifacts": len(artifacts), "claims": len(claim_ids)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-tag", action="store_true")
    args = parser.parse_args()
    result = verify(args.require_tag)
    print(json.dumps({"result": "pass", **result}, sort_keys=True))


if __name__ == "__main__":
    main()
