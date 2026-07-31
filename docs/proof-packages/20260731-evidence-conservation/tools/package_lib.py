from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

RECORD_HASH_EXCLUSIONS = {"content_sha256", "reviews", "admission_status"}


def canonical_json_bytes(value: Any, *, newline: bool = False) -> bytes:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return payload + (b"\n" if newline else b"")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value, newline=True))


def record_content_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key not in RECORD_HASH_EXCLUSIONS}


def record_content_sha256(record: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(record_content_payload(record)))


def candidate_record(
    *,
    schema: str,
    record_id: str,
    spec_sha256: str,
    created_at_utc: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "schema": schema,
        "record_id": record_id,
        "spec_sha256": spec_sha256,
        "created_at_utc": created_at_utc,
        "producer": {
            "actor_id": "codex",
            "role": "EVIDENCE_PACKAGE_GENERATOR",
        },
        "supersedes": None,
        "body": body,
        "content_sha256": "",
        "reviews": [],
        "admission_status": "CANDIDATE",
    }
    record["content_sha256"] = record_content_sha256(record)
    return record


def json_diff_paths(before: Any, after: Any, path: str = "") -> list[str]:
    if isinstance(before, dict) and isinstance(after, dict):
        differences: list[str] = []
        for key in sorted(set(before) | set(after)):
            child = f"{path}/{_escape_pointer(key)}"
            if key not in before or key not in after:
                differences.append(child)
            else:
                differences.extend(json_diff_paths(before[key], after[key], child))
        return differences
    if isinstance(before, list) and isinstance(after, list):
        if len(before) != len(after):
            return [path or "/"]
        differences = []
        for index, (left, right) in enumerate(zip(before, after, strict=True)):
            differences.extend(json_diff_paths(left, right, f"{path}/{index}"))
        return differences
    return [] if before == after else [path or "/"]


def semantic_diff_paths(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    return [path for path in json_diff_paths(before, after) if path != "/padding"]


def _escape_pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def extract_approved_spec(session_jsonl: Path) -> bytes:
    final_text: str | None = None
    for raw_line in session_jsonl.read_text(encoding="utf-8").splitlines():
        row = json.loads(raw_line)
        payload = row.get("payload", {})
        if (
            row.get("type") == "response_item"
            and payload.get("type") == "message"
            and payload.get("role") == "assistant"
            and payload.get("phase") == "final_answer"
        ):
            for item in payload.get("content", []):
                if item.get("type") == "output_text":
                    final_text = item.get("text")
    if final_text is None:
        raise ValueError("approved final answer was not found")
    start_marker = "# Final revised Evidence Conservation Mutation Pilot specification"
    end_marker = "`ADVANCE_TO_IMPLEMENTATION_PROMPT`"
    start = final_text.index(start_marker)
    end = final_text.index(end_marker, start) + len(end_marker)
    return final_text[start:end].rstrip().encode("utf-8") + b"\n"


def equalize_fixture_lengths(fixtures: dict[str, dict[str, Any]]) -> None:
    for fixture in fixtures.values():
        fixture["padding"] = ""
    target = max(len(canonical_json_bytes(value, newline=True)) for value in fixtures.values()) + 256
    for fixture in fixtures.values():
        current = len(canonical_json_bytes(fixture, newline=True))
        fixture["padding"] = "0" * (target - current)
        if len(canonical_json_bytes(fixture, newline=True)) != target:
            raise AssertionError("fixture padding did not equalize byte length")


def is_hex_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(character in "0123456789abcdef" for character in value)
