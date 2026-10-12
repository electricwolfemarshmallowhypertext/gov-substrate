"""Materialize or verify the pinned, ignored Bordair source records.

This script never rewrites records. It downloads exact source files by commit,
checks their SHA-256 values from the checked-in manifest, and leaves raw attack
text under ignored dist/ only.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.request import Request, build_opener


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests/data/bordair-source-manifest.json"
DESTINATION = ROOT / "dist/injection-source-review"
REPOSITORY = "https://raw.githubusercontent.com/Josh-blythe/bordair-multimodal"


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def source_files(manifest):
    files = {}
    for case in manifest["cases"]:
        source_path = case["source_path"]
        category = source_path.split("/")[1]
        existing = files.setdefault(category, {
            "source_path": source_path,
            "sha256": case["source_file_sha256"],
            "case_count": 0,
        })
        if existing["source_path"] != source_path or existing["sha256"] != case["source_file_sha256"]:
            raise RuntimeError("manifest_category_collision")
        existing["case_count"] += 1
    return files


def verify(manifest):
    verified = []
    for category, item in source_files(manifest).items():
        path = DESTINATION / f"{category}.json"
        raw = path.read_bytes()
        if sha256(raw) != item["sha256"]:
            raise RuntimeError(f"source_file_hash_mismatch:{category}")
        records = {record["id"]: record for record in json.loads(raw)}
        for case in manifest["cases"]:
            if case["source_path"] != item["source_path"]:
                continue
            record = records.get(case["id"])
            if type(record) is not dict or type(record.get("text")) is not str:
                raise RuntimeError(f"source_record_missing:{case['id']}")
            if sha256(record["text"].encode("utf-8")) != case["payload_utf8_sha256"]:
                raise RuntimeError(f"source_payload_hash_mismatch:{case['id']}")
        verified.append({"category": category, "source_file_sha256": item["sha256"],
                         "selected_cases": item["case_count"]})
    return verified


def fetch(manifest):
    DESTINATION.mkdir(parents=True, exist_ok=True)
    opener = build_opener()
    for category, item in source_files(manifest).items():
        url = f"{REPOSITORY}/{manifest['commit']}/{item['source_path']}"
        request = Request(url, headers={"Accept": "application/json"}, method="GET")
        with opener.open(request, timeout=30) as response:
            raw = response.read()
        if sha256(raw) != item["sha256"]:
            raise RuntimeError(f"downloaded_source_file_hash_mismatch:{category}")
        temporary = DESTINATION / f".{category}.{os.getpid()}.tmp"
        temporary.write_bytes(raw)
        os.replace(temporary, DESTINATION / f"{category}.json")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--fetch", action="store_true", help="Download exact pinned source files.")
    mode.add_argument("--verify", action="store_true", help="Verify locally cached source files only.")
    options = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if options.fetch:
        fetch(manifest)
    verified = verify(manifest)
    print(json.dumps({"result": "PASS", "commit": manifest["commit"], "files": verified}))


if __name__ == "__main__":
    main()
