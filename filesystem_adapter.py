"""Scoped UTF-8 file access for the Linux substrate container."""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path


MAX_CONTENT = 64 * 1024


def parts_of(path: str) -> list[str]:
    if (not isinstance(path, str) or not path or len(path) > 256 or
            path.startswith("/") or "\\" in path or "\x00" in path):
        raise ValueError("invalid_path")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("invalid_path")
    return parts


@contextmanager
def parent_fd(root: Path, parts: list[str]):
    if os.name != "posix":
        raise ValueError("linux_adapter_required")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=fd)
            os.close(fd)
            fd = next_fd
        yield fd
    finally:
        os.close(fd)


def check_target(root: Path, path: str) -> None:
    parts = parts_of(path)
    try:
        with parent_fd(root, parts) as fd:
            try:
                target = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            if not stat.S_ISREG(target.st_mode) or target.st_nlink != 1:
                raise ValueError("path_escape")
    except OSError as exc:
        raise ValueError("path_escape") from exc


def read_text(root: Path, path: str) -> dict:
    check_target(root, path)
    parts = parts_of(path)
    with parent_fd(root, parts) as directory:
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("path_escape")
            content = os.read(fd, MAX_CONTENT + 1)
            if len(content) > MAX_CONTENT:
                raise ValueError("file_too_large")
        finally:
            os.close(fd)
    return {"content": content.decode("utf-8"), "bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest()}


def write_text(root: Path, path: str, content: str) -> dict:
    if not isinstance(content, str):
        raise ValueError("invalid_content")
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_CONTENT:
        raise ValueError("file_too_large")
    check_target(root, path)
    parts = parts_of(path)
    with parent_fd(root, parts) as directory:
        temporary = f".substrate-{secrets.token_hex(12)}"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, parts[-1], src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
    return {"bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}


def workspace_snapshot(root: Path) -> dict:
    metadata = root.stat()
    entries = []
    for directory, names, files in os.walk(root, followlinks=False):
        for name in sorted([*names, *files]):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            entry = {"path": relative}
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                entry.update(kind="symlink", target=os.readlink(path))
            elif stat.S_ISDIR(info.st_mode):
                entry["kind"] = "directory"
            elif stat.S_ISREG(info.st_mode):
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                hash_value = hashlib.sha256()
                with os.fdopen(fd, "rb") as stream:
                    for chunk in iter(lambda: stream.read(64 * 1024), b""):
                        hash_value.update(chunk)
                entry.update(kind="file", sha256=hash_value.hexdigest(), size=info.st_size)
            else:
                entry["kind"] = "special"
            entries.append(entry)
    return {"root_device": metadata.st_dev, "root_inode": metadata.st_ino,
            "entries": sorted(entries, key=lambda item: item["path"])}
