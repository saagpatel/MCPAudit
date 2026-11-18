#!/usr/bin/env python3
"""Reproducible-build check: build the committed source twice and compare hashes.

Each build runs in its own fresh clone of HEAD, at paths of different lengths,
so uncommitted files, build caches and absolute paths cannot leak into the
result. With ``--reference DIR`` the script builds once and compares that build
against the files already in DIR (for example the ``dist/`` a release job is
about to publish), which is the second build.

The build command is run through the shell from the clone (or ``--subdir`` in
it). ``{out}`` in the command is replaced with an absolute, empty output
directory. The environment is inherited unchanged, so set SOURCE_DATE_EPOCH
(or anything else the build reads) the same way for every build being compared.

Exit status: 0 when every artifact matches byte for byte, 1 on any mismatch,
2 on usage or build errors. Standard library only.
"""

from __future__ import annotations

import argparse
import fnmatch
import gzip
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

DEFAULT_PATTERNS = ("*.whl", "*.tar.gz", "*.tgz")


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifacts(directory: Path, patterns: tuple[str, ...]) -> dict[str, str]:
    return {
        path.name: _sha256(path)
        for path in sorted(directory.iterdir())
        if path.is_file() and any(fnmatch.fnmatch(path.name, p) for p in patterns)
    }


def _members(path: Path) -> dict[str, str]:
    """Return member name -> short description, used only to explain a mismatch."""
    found: dict[str, str] = {}
    if path.name.endswith(".whl") or path.name.endswith(".zip"):
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                body = hashlib.sha256(archive.read(info)).hexdigest()[:16]
                found[info.filename] = (
                    f"sha256={body} mtime={info.date_time} mode={info.external_attr >> 16:o}"
                )
    elif path.name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(path) as archive:
            for member in archive.getmembers():
                body = ""
                if member.isfile():
                    extracted = archive.extractfile(member)
                    body = hashlib.sha256(extracted.read() if extracted else b"").hexdigest()[:16]
                found[member.name] = (
                    f"sha256={body} mtime={member.mtime} mode={member.mode:o} owner={member.uid}:{member.gid}"
                )
    return found


def _explain(name: str, left: Path, right: Path) -> list[str]:
    try:
        a, b = _members(left / name), _members(right / name)
    except (OSError, EOFError, tarfile.TarError, zipfile.BadZipFile) as exc:
        return [f"    {name}: cannot open as an archive ({exc.__class__.__name__}); compare raw bytes"]
    if not a and not b:
        return [f"    {name}: not an archive this script can open"]
    lines = []
    for member in sorted(set(a) | set(b)):
        if a.get(member) != b.get(member):
            lines.append(
                f"    {name}::{member}\n"
                f"      first:  {a.get(member, '<absent>')}\n"
                f"      second: {b.get(member, '<absent>')}"
            )
    if not lines and name.endswith((".tar.gz", ".tgz")):
        try:
            same_tar = gzip.decompress((left / name).read_bytes()) == gzip.decompress(
                (right / name).read_bytes()
            )
        except (OSError, EOFError):
            same_tar = False
        if same_tar:
            lines.append(
                f"    {name}: uncompressed tar is identical;"
                " only the gzip stream differs (compressor or zlib build)"
            )
    if not lines:
        lines.append(f"    {name}: members identical; archive headers or ordering differ")
    return lines[:40]


def _build(root: Path, commit: str, workdir: Path, label: str, command: str, subdir: str) -> Path:
    source = workdir / label
    out = workdir / f"out-{label}"
    out.mkdir()
    subprocess.run(
        ["git", "clone", "--quiet", "--no-hardlinks", "--no-checkout", str(root), str(source)],
        check=True,
    )
    subprocess.run(["git", "-C", str(source), "checkout", "--quiet", "--detach", commit], check=True)
    cwd = source / subdir if subdir else source
    rendered = command.replace("{out}", shlex.quote(str(out)))
    print(f"[repro] build {label}: {rendered}", flush=True)
    result = subprocess.run(rendered, shell=True, cwd=cwd)
    if result.returncode != 0:
        print(f"[repro] build {label} failed with exit code {result.returncode}", file=sys.stderr)
        raise SystemExit(2)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--build", required=True, help="shell command; {out} is the output directory")
    parser.add_argument("--reference", type=Path, help="compare one fresh build against this directory")
    parser.add_argument("--subdir", default="", help="run the build from this subdirectory of the clone")
    parser.add_argument(
        "--pattern", action="append", help=f"artifact glob (default: {', '.join(DEFAULT_PATTERNS)})"
    )
    parser.add_argument("--report", type=Path, help="write a JSON report here")
    parser.add_argument("--keep", action="store_true", help="keep the temporary clones and outputs")
    args = parser.parse_args(argv)

    patterns = tuple(args.pattern or DEFAULT_PATTERNS)
    if "{out}" not in args.build:
        parser.error("--build must contain {out}")
    root = Path(_git(Path.cwd(), "rev-parse", "--show-toplevel"))
    commit = _git(root, "rev-parse", "HEAD")
    dirty = bool(_git(root, "status", "--porcelain", "--untracked-files=no"))
    if dirty:
        print(
            "[repro] warning: tracked files differ from HEAD; only committed source is rebuilt",
            file=sys.stderr,
        )

    workdir = Path(tempfile.mkdtemp(prefix="repro-"))
    try:
        if args.reference:
            first_dir = args.reference.resolve()
            first_label = f"reference ({args.reference})"
        else:
            first_dir = _build(root, commit, workdir, "a", args.build, args.subdir)
            first_label = "build a"
        # A longer path than build "a" so absolute paths embedded in output show up as a difference.
        second_dir = _build(root, commit, workdir, "bb-second-build", args.build, args.subdir)

        first, second = _artifacts(first_dir, patterns), _artifacts(second_dir, patterns)
        problems: list[str] = []
        if not first:
            problems.append(f"{first_label} produced no artifacts matching {patterns}")
        if set(first) != set(second):
            problems.append(f"file sets differ: {sorted(first)} vs {sorted(second)}")
        for name in sorted(set(first) & set(second)):
            status = "match" if first[name] == second[name] else "MISMATCH"
            print(
                f"[repro] {status} {name}\n"
                f"          {first_label}: {first[name]}\n"
                f"          build bb:  {second[name]}"
            )
            if first[name] != second[name]:
                problems.append(f"{name} differs")
                print("\n".join(_explain(name, first_dir, second_dir)))

        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(
                json.dumps(
                    {
                        "schema": "reproducible-build-check.v1",
                        "commit": commit,
                        "build_command": args.build,
                        "subdir": args.subdir,
                        "source_date_epoch": os.environ.get("SOURCE_DATE_EPOCH"),
                        "first": {"label": first_label, "sha256": first},
                        "second": {"label": "fresh clone rebuild", "sha256": second},
                        "reproducible": not problems,
                        "problems": problems,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )
        if problems:
            print("[repro] NOT reproducible:\n  " + "\n  ".join(problems), file=sys.stderr)
            return 1
        print(f"[repro] reproducible: {len(first)} artifact(s) identical at {commit}")
        return 0
    except subprocess.CalledProcessError as exc:
        print(f"[repro] setup command failed: {exc}", file=sys.stderr)
        return 2
    finally:
        if args.keep:
            print(f"[repro] kept {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
