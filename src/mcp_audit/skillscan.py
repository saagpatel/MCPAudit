"""Deterministic offline scanner for agent skills and MCP bundles."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import unicodedata
import zipfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Final, cast

import yaml

from mcp_audit import __version__
from mcp_audit.redaction import redact_text
from mcp_audit.skillscan_models import (
    SkillscanCheck,
    SkillscanDetail,
    SkillscanReport,
    SkillscanRuleset,
    SkillscanSubject,
)

INJECTION_CHECK: Final = "scan/injection-patterns"
OBFUSCATED_EGRESS_CHECK: Final = "scan/obfuscated-egress"
DYNAMIC_FETCH_CHECK: Final = "scan/dynamic-fetch-presence"
PERMISSION_CHECK: Final = "scan/permission-surface"

RULE_TABLE: Final[dict[str, dict[str, object]]] = {
    "SKILL001": {
        "check": INJECTION_CHECK,
        "patterns": [
            r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|earlier)\s+instructions?\b",
            r"(?i)\bdisregard\s+(?:(?:all|your|previous|prior)\s+)?instructions?\b",
            r"(?i)\byou\s+must\s+now\b",
            r"(?i)\boverride\s+(?:the\s+)?(?:previous|prior|system)\s+instructions?\b",
        ],
        "version": "1",
    },
    "SKILL002": {
        "check": INJECTION_CHECK,
        "patterns": ["\\u200b", "\\u200c", "\\u200d", "\\u2060", "\\ufeff"],
        "version": "1",
    },
    "SKILL003": {
        "check": INJECTION_CHECK,
        "pattern": (
            r"(?is)<!--(?:(?!-->).)*\b(?:ignore|disregard|override|execute|run|must|install|send|reveal)\b"
            r"(?:(?!-->).)*-->"
        ),
        "version": "1",
    },
    "SKILL004": {
        "check": INJECTION_CHECK,
        "pattern": r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=])",
        "version": "1",
    },
    "SKILL005": {
        "check": OBFUSCATED_EGRESS_CHECK,
        "pattern": (
            r"(?is)(?:b64decode|urlsafe_b64decode|(?:bytes|bytearray)\.fromhex|"
            r"Buffer\.from\s*\([^)]*['\"](?:base64|hex)['\"]|atob\s*\()"
            r"[\s\S]{0,400}(?:https?://|requests\.|urllib\.|fetch\s*\(|curl|wget|subprocess\.|"
            r"os\.system|spawn\s*\()"
        ),
        "version": "1",
    },
    "SKILL006": {
        "check": OBFUSCATED_EGRESS_CHECK,
        "patterns": [
            r"(?im)^\s*(?:host|hostname|domain)\w*\s*=\s*[^\n]*(?:['\"][^'\"]+['\"]\s*\+\s*['\"]|chr\s*\()",
            r"(?im)^\s*(?:url|endpoint)\w*\s*=\s*[^\n]*chr\s*\(",
        ],
        "version": "1",
    },
    "SKILL007": {
        "check": OBFUSCATED_EGRESS_CHECK,
        "patterns": [
            (
                r"(?ims)^\s*(?:const\s+|let\s+|var\s+)?([A-Za-z_]\w*)\s*=\s*"
                r"(?=[^\n]*(?:\+|\.join\(|f['\"]))"
                r"(?=[^\n]*(?:http|scheme|host|url))[^\n]*\n(?:[^\n]*\n){0,8}?"
                r"[^\n]*(?:requests\.(?:get|post|put|delete)|urllib\.(?:request\.)?urlopen|fetch)"
                r"\s*\([^\n)]*\1"
            ),
            (
                r"(?ims)^\s*(?:const\s+|let\s+|var\s+)?([A-Za-z_]\w*)\s*=\s*"
                r"(?=[^\n]*(?:\+|\.join\(|f['\"]))"
                r"(?=[^\n]*(?:http|scheme|host|url))[^\n]*\n(?:[^\n]*\n){0,8}?"
                r"[^\n]*(?:curl|wget)\b[^\n]*\$\{?\1\}?"
            ),
            (
                r"(?ims)^\s*([A-Za-z_]\w*)\s*=\s*['\"]?"
                r"(?=[^\n]*\$\{?(?:scheme|host|url))[^\n]*\n(?:[^\n]*\n){0,8}?"
                r"[^\n]*(?:curl|wget)\b[^\n]*\$\{?\1\}?"
            ),
        ],
        "version": "1",
    },
    "SKILL008": {
        "check": DYNAMIC_FETCH_CHECK,
        "pattern": r"(?im)\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:ba|z|k)?sh\b",
        "version": "1",
    },
    "SKILL009": {
        "check": DYNAMIC_FETCH_CHECK,
        "pattern": (
            r"(?im)\b(?:eval|exec)\s*\([^\n]{0,400}"
            r"(?:requests\.(?:get|post)|urllib\.(?:request\.)?urlopen|fetch\s*\()"
        ),
        "version": "1",
    },
    "SKILL010": {
        "check": DYNAMIC_FETCH_CHECK,
        "pattern": (
            r"(?im)(?:subprocess\.(?:run|call|Popen|check_call|check_output)|os\.system)"
            r"\s*\([^\n]{0,400}\b(?:curl|wget)\b"
        ),
        "version": "1",
    },
    "SKILL011": {
        "check": DYNAMIC_FETCH_CHECK,
        "patterns": ["install", "postinstall"],
        "version": "1",
    },
    "SKILL012": {
        "check": PERMISSION_CHECK,
        "patterns": ["*", "tool:*", "namespace__*", "Command(*)"],
        "version": "1",
    },
    "SKILL013": {
        "check": PERMISSION_CHECK,
        "patterns": ["network", "filesystem", "exec"],
        "version": "1",
    },
}

RULESET_CONFIG_SHA256: Final = hashlib.sha256(
    json.dumps(RULE_TABLE, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
).hexdigest()

_CHECK_ORDER: Final = [
    INJECTION_CHECK,
    OBFUSCATED_EGRESS_CHECK,
    DYNAMIC_FETCH_CHECK,
    PERMISSION_CHECK,
]
_TEXT_SUFFIXES: Final = {".md", ".txt", ".yaml", ".yml"}
_CODE_SUFFIXES: Final = {".py", ".js", ".mjs", ".ts", ".sh", ".rb"}
_ZERO_WIDTH: Final = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}
_TOKEN_RE: Final = re.compile(r"[A-Za-z0-9+/=_-]{32,}")
_BASE64_RE: Final = re.compile(cast(str, RULE_TABLE["SKILL004"]["pattern"]))

# Archive expansion caps: a static scan must not be OOM-killed by a decompression
# bomb in an attacker-controlled .mcpb/.zip before it can report.
_MAX_ARCHIVE_MEMBERS: Final = 10_000
_MAX_MEMBER_BYTES: Final = 64 * 1024 * 1024  # 64 MiB per inflated member
_MAX_TOTAL_BYTES: Final = 512 * 1024 * 1024  # 512 MiB inflated across the bundle


class SkillscanInputError(ValueError):
    """The supplied skill or bundle cannot be scanned safely."""


@dataclass(frozen=True, slots=True)
class BundleFile:
    """One included regular file addressed relative to the bundle root."""

    path: str
    data: bytes


@dataclass(frozen=True, slots=True)
class Bundle:
    """Loaded bundle bytes plus their contract identity."""

    subject: SkillscanSubject
    files: tuple[BundleFile, ...]


CheckRunner = Callable[[Bundle], list[SkillscanDetail] | None]


def canonical_ruleset_bytes() -> bytes:
    """Return the exact ruleset bytes bound into ``config_sha256``."""
    return json.dumps(
        RULE_TABLE,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _read_regular_file(path: Path) -> bytes:
    """Read one regular file without following a final-component symlink."""
    try:
        before = path.lstat()
    except OSError as exc:
        raise SkillscanInputError(f"cannot inspect input file: {path.name}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise SkillscanInputError(f"input is not a regular file: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SkillscanInputError(f"cannot safely open input file: {path.name}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise SkillscanInputError(f"input changed while opening: {path.name}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _directory_files(root: Path) -> tuple[BundleFile, ...]:
    files: list[BundleFile] = []
    normalized_paths: dict[str, str] = {}

    def visit(directory: Path, parts: tuple[str, ...]) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise SkillscanInputError("cannot enumerate bundle directory") from exc
        for entry in entries:
            raw_parts = (*parts, entry.name)
            display_path = "/".join(raw_parts)
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise SkillscanInputError(f"cannot inspect bundle entry: {display_path}") from exc
            if stat.S_ISLNK(entry_stat.st_mode):
                raise SkillscanInputError(f"symlinks are not allowed: {display_path}")
            if stat.S_ISDIR(entry_stat.st_mode):
                if entry.name not in {".git", "__pycache__"}:
                    visit(Path(entry.path), raw_parts)
                continue
            if entry.name == ".DS_Store":
                continue
            if not stat.S_ISREG(entry_stat.st_mode):
                raise SkillscanInputError(f"unsupported bundle entry: {display_path}")
            normalized = unicodedata.normalize("NFC", display_path)
            previous = normalized_paths.get(normalized)
            if previous is not None and previous != display_path:
                raise SkillscanInputError(
                    f"paths collide after NFC normalization: {previous} and {display_path}"
                )
            normalized_paths[normalized] = display_path
            files.append(BundleFile(path=normalized, data=_read_regular_file(Path(entry.path))))

    visit(root, ())
    files.sort(key=lambda item: item.path)
    if not files:
        raise SkillscanInputError("bundle directory contains no included files")
    return tuple(files)


def _directory_digest(files: Iterable[BundleFile]) -> str:
    manifest = {item.path: hashlib.sha256(item.data).hexdigest() for item in files}
    canonical = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _normalized_archive_path(name: str) -> str:
    normalized = unicodedata.normalize("NFC", name)
    path = PurePosixPath(normalized)
    if not normalized or normalized.startswith("/") or ".." in path.parts:
        raise SkillscanInputError("archive contains an unsafe member path")
    return path.as_posix()


def _archive_files(raw: bytes) -> tuple[BundleFile, ...]:
    files: list[BundleFile] = []
    seen: dict[str, str] = {}
    total_bytes = 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            if len(members) > _MAX_ARCHIVE_MEMBERS:
                raise SkillscanInputError(
                    f"archive has {len(members)} members, exceeding the {_MAX_ARCHIVE_MEMBERS} cap"
                )
            for info in members:
                normalized = _normalized_archive_path(info.filename)
                unix_mode = (info.external_attr >> 16) & 0o170000
                if unix_mode == stat.S_IFLNK:
                    raise SkillscanInputError(f"archive symlinks are not allowed: {normalized}")
                if info.is_dir():
                    continue
                if info.flag_bits & 0x1:
                    raise SkillscanInputError("encrypted archive members are not supported")
                # Reject on the declared size before inflating, so a decompression
                # bomb cannot be read into memory in the first place.
                if info.file_size > _MAX_MEMBER_BYTES:
                    raise SkillscanInputError(
                        f"archive member {normalized} inflates to {info.file_size} bytes, "
                        f"exceeding the {_MAX_MEMBER_BYTES}-byte per-member cap"
                    )
                total_bytes += info.file_size
                if total_bytes > _MAX_TOTAL_BYTES:
                    raise SkillscanInputError(f"archive inflates past the {_MAX_TOTAL_BYTES}-byte total cap")
                previous = seen.get(normalized)
                if previous is not None:
                    raise SkillscanInputError(
                        f"archive paths collide after NFC normalization: {previous} and {info.filename}"
                    )
                seen[normalized] = info.filename
                data = archive.read(info)
                # The central-directory size is advisory; enforce the real inflated
                # length too, in case a crafted header understates it.
                if len(data) > _MAX_MEMBER_BYTES:
                    raise SkillscanInputError(f"archive member {normalized} inflated past its declared size")
                files.append(BundleFile(path=normalized, data=data))
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        raise SkillscanInputError("input is not a readable ZIP bundle") from exc
    files.sort(key=lambda item: item.path)
    return tuple(files)


def load_bundle(path: Path, name: str | None = None) -> Bundle:
    """Load a directory or archive and derive its exact contract subject."""
    try:
        entry = path.lstat()
    except OSError as exc:
        raise SkillscanInputError("input path does not exist or cannot be inspected") from exc
    if stat.S_ISLNK(entry.st_mode):
        raise SkillscanInputError("input path must not be a symlink")
    if stat.S_ISDIR(entry.st_mode):
        files = _directory_files(path)
        subject = SkillscanSubject(
            kind="skill_bundle",
            name=name or path.name,
            digest=_directory_digest(files),
            media_type="application/vnd.checkseal.bundle-manifest+json",
        )
        return Bundle(subject=subject, files=files)
    if not stat.S_ISREG(entry.st_mode):
        raise SkillscanInputError("input path must be a directory or ZIP bundle")
    if path.suffix.lower() not in {".mcpb", ".zip"}:
        raise SkillscanInputError("archive input must use a .mcpb or .zip extension")
    raw = _read_regular_file(path)
    subject = SkillscanSubject(
        kind="mcp_server",
        name=name or path.stem,
        digest=hashlib.sha256(raw).hexdigest(),
        media_type="application/vnd.mcpb+zip",
    )
    return Bundle(subject=subject, files=_archive_files(raw))


def _text(file: BundleFile) -> str:
    return file.data.decode("utf-8", errors="replace")


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _safe_excerpt(text: str, start: int, end: int) -> str:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end < 0:
        line_end = len(text)
    excerpt = " ".join(text[line_start:line_end].split())
    for character in _ZERO_WIDTH:
        excerpt = excerpt.replace(character, "[zero-width]")
    excerpt = _BASE64_RE.sub("[encoded-data]", excerpt)
    # Credential-assignment redaction (password=…, Bearer …, url userinfo) before
    # the coarse 32+ char token pass, so short secrets never reach the report.
    excerpt = redact_text(excerpt)
    excerpt = _TOKEN_RE.sub("[redacted-token]", excerpt)
    if len(excerpt) > 120:
        excerpt = f"{excerpt[:117]}..."
    return excerpt


def _detail(rule_id: str, file: BundleFile, text: str, match: re.Match[str]) -> SkillscanDetail:
    return SkillscanDetail(
        rule_id=rule_id,
        path=file.path,
        line=_line_number(text, match.start()),
        excerpt=_safe_excerpt(text, match.start(), match.end()),
    )


def _rule_patterns(rule_id: str) -> list[str]:
    definition = RULE_TABLE[rule_id]
    if "pattern" in definition:
        return [cast(str, definition["pattern"])]
    return cast(list[str], definition["patterns"])


def _yaml_description_segments(text: str) -> list[tuple[int, str]]:
    segments: list[tuple[int, str]] = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"^\s*description\s*:\s*(.*)$", line, re.IGNORECASE)
        if match is None:
            continue
        value = match.group(1).strip()
        collected = [value] if value not in {"", "|", ">", "|-", ">-"} else []
        base_indent = len(line) - len(line.lstrip())
        for following in lines[index + 1 :]:
            if not following.strip():
                continue
            indent = len(following) - len(following.lstrip())
            if indent <= base_indent:
                break
            collected.append(following.strip())
        segments.append((index + 1, " ".join(collected)))
    return segments


def _scan_patterns(
    rule_id: str,
    file: BundleFile,
    text: str,
    *,
    line_offset: int = 0,
) -> list[SkillscanDetail]:
    findings: list[SkillscanDetail] = []
    for pattern in _rule_patterns(rule_id):
        for match in re.finditer(pattern, text):
            detail = _detail(rule_id, file, text, match)
            if line_offset:
                detail = detail.model_copy(update={"line": detail.line + line_offset})
            findings.append(detail)
    return findings


def _scan_injection(bundle: Bundle) -> list[SkillscanDetail] | None:
    candidates = [item for item in bundle.files if Path(item.path).suffix.lower() in _TEXT_SUFFIXES]
    if not candidates:
        return None
    findings: list[SkillscanDetail] = []
    for file in candidates:
        text = _text(file)
        suffix = Path(file.path).suffix.lower()
        segments = [(1, text)] if suffix in {".md", ".txt"} else _yaml_description_segments(text)
        for base_line, segment in segments:
            for rule_id in ("SKILL001", "SKILL003", "SKILL004"):
                findings.extend(_scan_patterns(rule_id, file, segment, line_offset=base_line - 1))
            for match in re.finditer("[\u200b\u200c\u200d\u2060\ufeff]", segment):
                detail = _detail("SKILL002", file, segment, match)
                findings.append(detail.model_copy(update={"line": detail.line + base_line - 1}))
    return findings


def _scan_obfuscated_egress(bundle: Bundle) -> list[SkillscanDetail] | None:
    candidates = [item for item in bundle.files if Path(item.path).suffix.lower() in _CODE_SUFFIXES]
    if not candidates:
        return None
    findings: list[SkillscanDetail] = []
    for file in candidates:
        text = _text(file)
        for rule_id in ("SKILL005", "SKILL006", "SKILL007"):
            findings.extend(_scan_patterns(rule_id, file, text))
    return findings


def _package_script_findings(file: BundleFile) -> list[SkillscanDetail]:
    text = _text(file)
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        # A malformed manifest is an unparseable file, not a scanner failure: skip
        # it so findings already accumulated from other files in this check survive.
        return []
    if not isinstance(payload, dict):
        return []
    scripts = payload.get("scripts")
    if not isinstance(scripts, dict):
        return []
    findings: list[SkillscanDetail] = []
    for lifecycle in ("install", "postinstall"):
        command = scripts.get(lifecycle)
        if not isinstance(command, str) or not command.strip():
            continue
        match = re.search(rf"(?m)['\"]{re.escape(lifecycle)}['\"]\s*:", text)
        line = _line_number(text, match.start()) if match is not None else 1
        findings.append(
            SkillscanDetail(
                rule_id="SKILL011",
                path=file.path,
                line=line,
                excerpt=f"package lifecycle script: {lifecycle}",
            )
        )
    return findings


def _scan_dynamic_fetch(bundle: Bundle) -> list[SkillscanDetail] | None:
    code_files = [item for item in bundle.files if Path(item.path).suffix.lower() in _CODE_SUFFIXES]
    package_files = [item for item in bundle.files if PurePosixPath(item.path).name == "package.json"]
    if not code_files and not package_files:
        return None
    findings: list[SkillscanDetail] = []
    for file in code_files:
        text = _text(file)
        for rule_id in ("SKILL008", "SKILL009", "SKILL010"):
            findings.extend(_scan_patterns(rule_id, file, text))
    for file in package_files:
        findings.extend(_package_script_findings(file))
    return findings


def _frontmatter(text: str) -> Mapping[str, Any] | None:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    for index in range(1, len(lines)):
        if lines[index].strip() != "---":
            continue
        try:
            payload = yaml.safe_load("\n".join(lines[1:index]))
        except yaml.YAMLError:
            # Malformed frontmatter is an unparseable file, not a scanner failure.
            return {}
        return payload if isinstance(payload, dict) else {}
    return None


def _flatten_grants(value: object) -> list[str]:
    if isinstance(value, str):
        return [item for item in re.split(r"[,\s]+", value) if item]
    if isinstance(value, list):
        grants: list[str] = []
        for item in value:
            grants.extend(_flatten_grants(item))
        return grants
    if isinstance(value, dict):
        grants = []
        for key, nested in value.items():
            if nested is True:
                grants.append(str(key))
            elif nested is not False and nested is not None:
                grants.extend(_flatten_grants(nested))
        return grants
    return []


def _permission_values(value: object) -> list[str]:
    grants: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized_key = str(key).lower().replace("_", "-")
            if normalized_key in {"permissions", "allowed-tools"}:
                grants.extend(_flatten_grants(nested))
            grants.extend(_permission_values(nested))
    elif isinstance(value, list):
        for nested in value:
            grants.extend(_permission_values(nested))
    return grants


def _declared_permissions(bundle: Bundle) -> tuple[bool, list[tuple[BundleFile, list[str]]]]:
    declared = False
    surfaces: list[tuple[BundleFile, list[str]]] = []
    for file in bundle.files:
        basename = PurePosixPath(file.path).name
        grants: list[str] = []
        if basename == "SKILL.md":
            frontmatter = _frontmatter(_text(file))
            if frontmatter is not None and "allowed-tools" in frontmatter:
                declared = True
                grants.extend(_flatten_grants(frontmatter["allowed-tools"]))
        if basename in {"plugin.json", "manifest.json"}:
            try:
                payload = json.loads(_text(file))
            except (json.JSONDecodeError, ValueError):
                # Unparseable manifest: skip this file, keep other files' grants.
                payload = None
            if payload is not None:
                extracted = _permission_values(payload)
                if extracted or (isinstance(payload, dict) and "permissions" in payload):
                    declared = True
                grants.extend(extracted)
        if grants:
            surfaces.append((file, sorted(set(grants))))
    return declared, surfaces


def _grant_categories(grants: Iterable[str]) -> set[str]:
    categories: set[str] = set()
    for grant in grants:
        lowered = grant.lower()
        if any(token in lowered for token in ("network", "http", "fetch", "web", "curl", "wget", "socket")):
            categories.add("network")
        if any(token in lowered for token in ("file", "filesystem", "path", "directory", "read", "write")):
            categories.add("filesystem")
        if any(token in lowered for token in ("exec", "shell", "bash", "command", "subprocess", "terminal")):
            categories.add("exec")
    return categories


def _scan_permissions(bundle: Bundle) -> list[SkillscanDetail] | None:
    declared, surfaces = _declared_permissions(bundle)
    if not declared:
        return None
    findings: list[SkillscanDetail] = []
    all_grants: list[str] = []
    for file, grants in surfaces:
        all_grants.extend(grants)
        wildcard = [grant for grant in grants if "*" in grant]
        if wildcard:
            findings.append(
                SkillscanDetail(
                    rule_id="SKILL012",
                    path=file.path,
                    line=1,
                    excerpt=f"wildcard grant: {_safe_grant_list(wildcard)}",
                )
            )
    categories = _grant_categories(all_grants)
    if {"network", "filesystem", "exec"}.issubset(categories):
        path = surfaces[0][0].path if surfaces else ""
        findings.append(
            SkillscanDetail(
                rule_id="SKILL013",
                path=path,
                line=1,
                excerpt="combined grants: exec, filesystem, network",
            )
        )
    return findings


def _safe_grant_list(grants: Iterable[str]) -> str:
    joined = ", ".join(sorted(set(grants)))
    joined = _TOKEN_RE.sub("[redacted-token]", joined)
    return joined if len(joined) <= 90 else f"{joined[:87]}..."


def _rule_ids_for_check(check_id: str) -> list[str]:
    return [rule_id for rule_id, definition in RULE_TABLE.items() if definition["check"] == check_id]


def _error_check(check_id: str, exc: Exception) -> SkillscanCheck:
    rule_ids = _rule_ids_for_check(check_id)
    reason = f"{type(exc).__name__}: {exc}"
    reason = _TOKEN_RE.sub("[redacted-token]", " ".join(reason.split()))
    if len(reason) > 120:
        reason = f"{reason[:117]}..."
    return SkillscanCheck(
        id=cast(Any, check_id),
        result="error",
        findings=0,
        rule_ids=rule_ids,
        detail=[SkillscanDetail(rule_id=rule_ids[0], path="", line=0, excerpt=reason)],
    )


def _run_check(check_id: str, runner: CheckRunner, bundle: Bundle) -> SkillscanCheck | None:
    try:
        findings = runner(bundle)
    except Exception as exc:  # Per-check isolation is part of skillscan-report/v1.
        return _error_check(check_id, exc)
    if findings is None:
        return None
    unique = {(item.rule_id, item.path, item.line, item.excerpt): item for item in findings}
    ordered = [unique[key] for key in sorted(unique)]
    return SkillscanCheck(
        id=cast(Any, check_id),
        result="fail" if ordered else "pass",
        findings=len(ordered),
        rule_ids=_rule_ids_for_check(check_id),
        detail=ordered,
    )


def scan_path(path: Path, name: str | None = None, ran_at: str | None = None) -> SkillscanReport:
    """Scan one bundle without network access or executing bundle content."""
    bundle = load_bundle(path, name=name)
    runners: dict[str, CheckRunner] = {
        INJECTION_CHECK: _scan_injection,
        OBFUSCATED_EGRESS_CHECK: _scan_obfuscated_egress,
        DYNAMIC_FETCH_CHECK: _scan_dynamic_fetch,
        PERMISSION_CHECK: _scan_permissions,
    }
    checks = [
        check for check_id in _CHECK_ORDER if (check := _run_check(check_id, runners[check_id], bundle))
    ]
    participated = [rule_id for check in checks for rule_id in check.rule_ids]
    timestamp = ran_at or datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    return SkillscanReport(
        scanner_version=__version__,
        ran_at=timestamp,
        subject=bundle.subject,
        ruleset=SkillscanRuleset(
            config_sha256=hashlib.sha256(canonical_ruleset_bytes()).hexdigest(),
            rules=participated,
        ),
        checks=checks,
    )
