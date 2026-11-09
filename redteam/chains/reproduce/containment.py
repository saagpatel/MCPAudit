"""Descriptor-relative canary I/O and identity-checked teardown."""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import stat
import sys
from pathlib import Path


class CanaryFailure(Exception):
    """A containment or evidence requirement was not met."""


def _directory(path: Path) -> int:
    """Open every component without following links, including ancestors."""
    if not path.is_absolute() or ".." in path.parts:
        raise CanaryFailure("canary path must be absolute without parent traversal")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def prepare_parent(path: Path) -> Path:
    """Create parents without traversing a caller-supplied symlink."""
    absolute = path.absolute()
    if ".." in absolute.parts:
        raise CanaryFailure("canary parent must not contain parent traversal")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise CanaryFailure("canary parent must be owned by this user and not writable by others")
    finally:
        os.close(descriptor)
    return absolute


class PrivateCanary:
    """Pin the created directory; never write through or remove a replacement."""

    def __init__(self, parent: Path, prefix: str) -> None:
        self.parent_fd = _directory(parent)
        self.name = prefix + secrets.token_hex(12)
        created = False
        try:
            os.mkdir(self.name, mode=0o700, dir_fd=self.parent_fd)
            created = True
            self.fd = os.open(self.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.parent_fd)
        except BaseException:
            try:
                if created:
                    # rmdir can only remove an empty directory, never a link
                    # target or an injected tree, even if opening it failed.
                    os.rmdir(self.name, dir_fd=self.parent_fd)
            finally:
                os.close(self.parent_fd)
            raise
        self.root = parent / self.name
        self.identity = os.fstat(self.fd)

    def verify(self) -> None:
        descriptor = _directory(self.root)
        try:
            info = os.fstat(descriptor)
            if (info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode)) != (
                self.identity.st_dev,
                self.identity.st_ino,
                0o700,
            ):
                raise CanaryFailure("canary directory identity changed")
        finally:
            os.close(descriptor)

    def _parent(self, relative: str) -> tuple[int, str]:
        self.verify()
        path = Path(relative)
        if path.is_absolute() or not path.parts or any(part in {".", ".."} for part in path.parts):
            raise CanaryFailure("invalid relative canary path")
        descriptor = os.dup(self.fd)
        try:
            for part in path.parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            return descriptor, path.name
        except BaseException:
            os.close(descriptor)
            raise

    def mkdir(self, relative: str) -> None:
        descriptor, name = self._parent(relative)
        try:
            os.mkdir(name, mode=0o700, dir_fd=descriptor)
        finally:
            os.close(descriptor)

    def write(self, relative: str, data: bytes) -> None:
        descriptor, name = self._parent(relative)
        try:
            fd = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=descriptor
            )
            with os.fdopen(fd, "wb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise CanaryFailure("canary write target is not a private regular file")
                stream.truncate()
                stream.write(data)
        finally:
            os.close(descriptor)

    def snapshot(self, *, exclude_git: bool = False) -> dict[str, str]:
        self.verify()
        result: dict[str, str] = {}

        def visit(descriptor: int, prefix: str) -> None:
            for name in sorted(os.listdir(descriptor)):
                relative = prefix + name
                if exclude_git and relative == "repo/.git":
                    continue
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
                try:
                    info = os.fstat(fd)
                    if stat.S_ISDIR(info.st_mode):
                        value = "directory"
                        visit(fd, relative + "/")
                    elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                        digest = hashlib.sha256()
                        while chunk := os.read(fd, 65536):
                            digest.update(chunk)
                        value = digest.hexdigest()
                    else:
                        raise CanaryFailure("unexpected non-private canary entry")
                    result[relative] = f"{stat.S_IMODE(info.st_mode)}:{value}"
                finally:
                    os.close(fd)

        visit(self.fd, "")
        return result

    def teardown(self) -> None:
        try:
            self.verify()
            if not shutil.rmtree.avoids_symlink_attacks:
                raise CanaryFailure("descriptor-relative teardown is unavailable")
            # Empty the pinned original, never a freshly looked-up top-level
            # replacement. rmtree's own top-level inode check cannot establish
            # that it opened the directory created by this canary.
            for name in os.listdir(self.fd):
                info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    shutil.rmtree(name, dir_fd=self.fd)
                else:
                    os.unlink(name, dir_fd=self.fd)
            self.verify()
            # Residual same-user race: a replacement empty directory could be
            # removed between this check and rmdir. The original-inode check
            # below rejects success, but does not make name removal atomic.
            os.rmdir(self.name, dir_fd=self.parent_fd)
            try:
                os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                # APFS can retain a nonzero link count for an open, removed
                # directory. F_GETPATH still distinguishes it from a renamed
                # original; a missing pathname alone does not prove removal.
                removed = os.fstat(self.fd).st_nlink == 0
                if not removed and sys.platform == "darwin":
                    import fcntl

                    getpath: object = getattr(fcntl, "F_GETPATH", None)
                    if isinstance(getpath, int):
                        actual = fcntl.fcntl(self.fd, getpath, bytes(1024)).split(b"\0", 1)[0]
                        removed = os.fsdecode(actual) == str(self.root)
                if removed and not os.listdir(self.fd):
                    return
            raise CanaryFailure("canary teardown did not remove the original directory")
        finally:
            os.close(self.fd)
            os.close(self.parent_fd)
