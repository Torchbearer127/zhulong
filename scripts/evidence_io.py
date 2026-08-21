#!/usr/bin/env python3
"""Host-owned evidence I/O primitives for the Docker verification wrapper."""
from __future__ import annotations

import json
import os
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


MAX_CONTROL_BYTES = 2 * 1024 * 1024
MAX_CAPTURE_BYTES = 16 * 1024 * 1024


class SafeEvidenceError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


def _error(code: str, message: str) -> SafeEvidenceError:
    return SafeEvidenceError(code, message)


def _root_and_parts(root: Path, path: Path) -> tuple[Path, tuple[str, ...]]:
    root = root.absolute()
    path = path.absolute()
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise _error("EVIDENCE_PATH_ESCAPE", "evidence path is outside its host-owned root") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise _error("EVIDENCE_PATH_UNSAFE", "evidence path contains an unsafe component")
    return root, relative.parts


def _require_owned_directory(path: Path, code: str) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise _error(code, "host-owned evidence directory is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise _error(code, "host-owned evidence directory is unsafe")
    return info


def ensure_host_directory(root: Path, path: Path) -> Path:
    """Create only real, current-user-owned descendant directories."""
    root, parts = _root_and_parts(root, path)
    _require_owned_directory(root, "EVIDENCE_ROOT_UNSAFE")
    current = root
    for part in parts:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            try:
                os.mkdir(current, 0o700)
            except OSError as exc:
                raise _error("EVIDENCE_DIRECTORY_CREATE_FAILED", "host evidence directory could not be created") from exc
            info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise _error("EVIDENCE_DIRECTORY_UNSAFE", "host evidence directory or ancestor is unsafe")
    return current


def _validate_parent(root: Path, path: Path) -> None:
    root, parts = _root_and_parts(root, path)
    _require_owned_directory(root, "EVIDENCE_ROOT_UNSAFE")
    current = root
    for part in parts[:-1]:
        current = current / part
        _require_owned_directory(current, "EVIDENCE_ANCESTOR_UNSAFE")


def _existing_identity(path: Path) -> tuple[int, int, int, int, int] | None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _error("EVIDENCE_TARGET_UNSAFE", "host evidence target cannot be inspected") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
        raise _error("EVIDENCE_TARGET_UNSAFE", "host evidence target must be a single-link owned regular file")
    return info.st_dev, info.st_ino, info.st_nlink, info.st_uid, info.st_mode


def _require_unchanged_target(path: Path, expected: tuple[int, int, int, int, int] | None) -> None:
    current = _existing_identity(path)
    if current != expected:
        raise _error("EVIDENCE_TARGET_DRIFT", "host evidence target changed during publication")


def _write_all(fd: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(fd, raw[offset:])
        if written <= 0:
            raise _error("EVIDENCE_WRITE_FAILED", "host evidence write was incomplete")
        offset += written


def _fsync_directory(path: Path) -> None:
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _read_bytes_with_identity(
    root: Path,
    path: Path,
    *,
    max_bytes: int,
    expected: tuple[int, int, int, int, int] | None = None,
) -> bytes:
    _validate_parent(root, path)
    before = _existing_identity(path)
    if before is None:
        raise _error("EVIDENCE_TARGET_MISSING", "host control evidence is missing")
    if expected is not None and before != expected:
        raise _error("EVIDENCE_TARGET_DRIFT", "host control evidence changed before safe open")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            identity = (opened.st_dev, opened.st_ino, opened.st_nlink, opened.st_uid, opened.st_mode)
            if identity != before or not stat.S_ISREG(opened.st_mode):
                raise _error("EVIDENCE_TARGET_DRIFT", "host control evidence changed during safe open")
            raw = b""
            while len(raw) <= max_bytes:
                chunk = os.read(fd, min(65536, max_bytes + 1 - len(raw)))
                if not chunk:
                    break
                raw += chunk
        finally:
            os.close(fd)
    except SafeEvidenceError:
        raise
    except OSError as exc:
        raise _error("EVIDENCE_READ_FAILED", "host control evidence could not be read safely") from exc
    if len(raw) > max_bytes:
        raise _error("EVIDENCE_SIZE_LIMIT", "host control evidence exceeds its size limit")
    return raw


def _rollback_publication(
    root: Path,
    path: Path,
    previous_raw: bytes | None,
    previous_mode: int | None,
    published: tuple[int, int, int, int, int],
) -> None:
    _validate_parent(root, path)
    _require_unchanged_target(path, published)
    if previous_raw is None:
        os.unlink(path)
        _fsync_directory(path.parent)
        return

    fd = -1
    temporary = ""
    file_fsync_error: OSError | None = None
    directory_fsync_error: OSError | None = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.rollback-", dir=path.parent)
        os.fchmod(fd, previous_mode if previous_mode is not None else 0o600)
        _write_all(fd, previous_raw)
        try:
            os.fsync(fd)
        except OSError as exc:
            file_fsync_error = exc
        os.close(fd)
        fd = -1
        _validate_parent(root, path)
        _require_unchanged_target(path, published)
        os.replace(temporary, path)
        temporary = ""
        try:
            _fsync_directory(path.parent)
        except OSError as exc:
            directory_fsync_error = exc
        if file_fsync_error is not None or directory_fsync_error is not None:
            raise _error("EVIDENCE_ROLLBACK_DURABILITY_FAILED", "old host evidence bytes were restored but rollback fsync failed")
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def atomic_write_bytes(
    root: Path,
    path: Path,
    raw: bytes,
    *,
    max_bytes: int = MAX_CONTROL_BYTES,
    post_write_validator: Callable[[bytes], None] | None = None,
) -> None:
    if len(raw) > max_bytes:
        raise _error("EVIDENCE_SIZE_LIMIT", "host control evidence exceeds its size limit")
    _validate_parent(root, path)
    expected = _existing_identity(path)
    previous_raw = (
        _read_bytes_with_identity(root, path, max_bytes=max_bytes, expected=expected)
        if expected is not None
        else None
    )
    previous_mode = stat.S_IMODE(os.lstat(path).st_mode) if expected is not None else None
    fd = -1
    temporary = ""
    published: tuple[int, int, int, int, int] | None = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
        os.fchmod(fd, 0o600)
        _write_all(fd, raw)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        _validate_parent(root, path)
        _require_unchanged_target(path, expected)
        os.replace(temporary, path)
        temporary = ""
        published = _existing_identity(path)
        if published is None:
            raise _error("EVIDENCE_TARGET_DRIFT", "published host evidence disappeared")
        _fsync_directory(path.parent)
        disk_raw = _read_bytes_with_identity(root, path, max_bytes=max_bytes, expected=published)
        if disk_raw != raw:
            raise _error("EVIDENCE_POST_WRITE_DRIFT", "published host evidence bytes do not match the requested bytes")
        if post_write_validator is not None:
            post_write_validator(disk_raw)
        _require_unchanged_target(path, published)
    except Exception as exc:
        if published is not None:
            try:
                _rollback_publication(root, path, previous_raw, previous_mode, published)
            except Exception as rollback_exc:
                if isinstance(rollback_exc, SafeEvidenceError):
                    raise rollback_exc from exc
                raise _error("EVIDENCE_ROLLBACK_FAILED", "old host evidence bytes could not be restored") from exc
        if isinstance(exc, SafeEvidenceError):
            raise
        if isinstance(exc, OSError):
            raise _error("EVIDENCE_ATOMIC_WRITE_FAILED", "host control evidence was not published") from exc
        raise
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def atomic_write_json(
    root: Path,
    path: Path,
    value: Any,
    *,
    post_write_validator: Callable[[bytes], None] | None = None,
) -> None:
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    atomic_write_bytes(root, path, raw, post_write_validator=post_write_validator)


def append_host_text(root: Path, path: Path, text: str, *, max_bytes: int = MAX_CONTROL_BYTES) -> None:
    """Append to a host-owned regular file through the same identity-checked replace."""
    _validate_parent(root, path)
    existing = b""
    identity = _existing_identity(path)
    if identity is not None:
        existing = safe_read_bytes(root, path, max_bytes=max_bytes)
    raw = existing + text.encode("utf-8", errors="replace")
    atomic_write_bytes(root, path, raw, max_bytes=max_bytes)


def safe_read_json(root: Path, path: Path) -> Any:
    try:
        raw = _read_bytes_with_identity(root, path, max_bytes=MAX_CONTROL_BYTES)
        return json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _error("EVIDENCE_JSON_INVALID", "host control evidence is not valid UTF-8 JSON") from exc


def safe_read_bytes(root: Path, path: Path, *, max_bytes: int = MAX_CONTROL_BYTES) -> bytes:
    return _read_bytes_with_identity(root, path, max_bytes=max_bytes)


def _publish_capture_file(root: Path, path: Path) -> int:
    _validate_parent(root, path)
    expected = _existing_identity(path)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.capture-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        _validate_parent(root, path)
        _require_unchanged_target(path, expected)
        os.replace(temporary, path)
        temporary = ""
        return fd
    except Exception:
        os.close(fd)
        raise
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def _capture_path_intact(root: Path, path: Path, fd: int) -> bool:
    try:
        _validate_parent(root, path)
        opened = os.fstat(fd)
        current = os.lstat(path)
    except (OSError, SafeEvidenceError):
        return False
    return (
        stat.S_ISREG(opened.st_mode)
        and stat.S_ISREG(current.st_mode)
        and not stat.S_ISLNK(current.st_mode)
        and opened.st_nlink == current.st_nlink == 1
        and opened.st_uid == current.st_uid == os.geteuid()
        and (opened.st_dev, opened.st_ino) == (current.st_dev, current.st_ino)
        and opened.st_size <= MAX_CAPTURE_BYTES
    )


def assert_publish_target_safe(root: Path, path: Path) -> None:
    """Fail closed if a host-owned control target is not safe to publish."""
    _validate_parent(root, path)
    _existing_identity(path)


def assert_capture_path_intact(root: Path, path: Path, fd: int) -> None:
    if not _capture_path_intact(root, path, fd):
        raise _error("EVIDENCE_CAPTURE_PATH_DRIFT", "captured Docker output path changed during execution")


def _read_capture_fd(fd: int) -> bytes:
    opened = os.fstat(fd)
    if opened.st_size > MAX_CAPTURE_BYTES:
        raise _error("EVIDENCE_SIZE_LIMIT", "captured Docker output exceeds its size limit")
    os.lseek(fd, 0, os.SEEK_SET)
    raw = b""
    while len(raw) < opened.st_size:
        chunk = os.read(fd, min(65536, opened.st_size - len(raw)))
        if not chunk:
            break
        raw += chunk
    return raw


def run_captured_command(
    root: Path,
    stdout_path: Path,
    stderr_path: Path,
    command: list[str],
    *,
    timeout: int,
    expected_oracle: str,
) -> dict[str, Any]:
    try:
        oracle = re.compile(expected_oracle, flags=re.MULTILINE) if expected_oracle else None
    except re.error as exc:
        raise _error("ORACLE_REGEX_INVALID", "expected oracle is not a valid regular expression") from exc
    stdout_fd = _publish_capture_file(root, stdout_path)
    stderr_fd = -1
    selector: selectors.BaseSelector | None = None
    try:
        stderr_fd = _publish_capture_file(root, stderr_path)
        timed_out = False
        command_started = False
        previous_handlers: dict[int, Any] = {}
        previous_mask: Any = None
        process: subprocess.Popen[bytes] | None = None
        streams: dict[int, bytearray] = {1: bytearray(), 2: bytearray()}
        limit_error: SafeEvidenceError | None = None

        def stop_process_group(signum: int) -> None:
            if process is None or process.poll() is not None:
                return
            try:
                os.killpg(process.pid, signum)
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass

        def interrupted(signum: int, _frame: Any) -> None:
            stop_process_group(signum)
            raise _error("EVIDENCE_CAPTURE_INTERRUPTED", "captured Docker command was interrupted")

        def append_capture(fd: int, stream_id: int, chunk: bytes) -> None:
            nonlocal limit_error
            if not chunk:
                return
            current = len(streams[stream_id])
            remaining = MAX_CAPTURE_BYTES - current
            if remaining <= 0:
                limit_error = _error("EVIDENCE_SIZE_LIMIT", "captured Docker output exceeds its size limit")
                return
            accepted = chunk[:remaining]
            _write_all(fd, accepted)
            streams[stream_id].extend(accepted)
            if len(accepted) != len(chunk):
                limit_error = _error("EVIDENCE_SIZE_LIMIT", "captured Docker output exceeds its size limit")

        try:
            for signum in (signal.SIGINT, signal.SIGTERM):
                previous_handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, interrupted)
            # Block external termination only across Popen and assignment of the
            # process object. A pending signal is delivered once the child PID is
            # known, so cleanup cannot race an unbound child.
            if hasattr(signal, "pthread_sigmask"):
                previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
                command_started = True
            finally:
                if previous_mask is not None:
                    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
                    previous_mask = None

            selector = selectors.DefaultSelector()
            assert process.stdout is not None and process.stderr is not None
            for stream_id, pipe in ((1, process.stdout), (2, process.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, stream_id)
            deadline = time.monotonic() + timeout
            while selector.get_map():
                if limit_error is not None:
                    stop_process_group(signal.SIGKILL)
                remaining_time = max(0.0, deadline - time.monotonic())
                if process.poll() is None and remaining_time <= 0:
                    timed_out = True
                    stop_process_group(signal.SIGKILL)
                events = selector.select(0.1 if process.poll() is None else 0)
                if not events and process.poll() is not None:
                    # A pipe can become readable after process exit; select one
                    # more time through the regular loop before closing it.
                    events = selector.select(0.05)
                for key, _ in events:
                    stream_id = int(key.data)
                    try:
                        chunk = os.read(key.fd, 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    append_capture(stdout_fd if stream_id == 1 else stderr_fd, stream_id, chunk)
                if limit_error is not None and process.poll() is not None:
                    # Continue draining already-buffered bytes only up to the
                    # hard cap, then close the pipes deterministically.
                    pass
            if process.poll() is None:
                process.wait(timeout=2)
        except FileNotFoundError as exc:
            _write_all(stderr_fd, (str(exc) + "\n").encode("utf-8", errors="replace"))
            process = None
        except OSError as exc:
            _write_all(stderr_fd, (str(exc) + "\n").encode("utf-8", errors="replace"))
            process = None
        finally:
            if selector is not None:
                selector.close()
            if previous_mask is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
        if limit_error is not None:
            raise limit_error
        os.fsync(stdout_fd)
        os.fsync(stderr_fd)
        stdout_intact = _capture_path_intact(root, stdout_path, stdout_fd)
        stderr_intact = _capture_path_intact(root, stderr_path, stderr_fd)
        stdout_bytes = bytes(streams[1])
        stderr_bytes = bytes(streams[2])
        text = (stdout_bytes + b"\n" + stderr_bytes).decode("utf-8", errors="ignore")
        return {
            "exit_code": 124 if timed_out else 127 if process is None else int(process.returncode),
            "oracle_matched": bool(oracle.search(text)) if oracle is not None else False,
            "resource_limit_detected": bool(re.search(r"out of memory|oom|memory limit|pids limit|cannot allocate memory|resource temporarily unavailable", text, re.I)),
            "capture_integrity": stdout_intact and stderr_intact,
            "command_started": command_started,
            "stdout_bytes": len(stdout_bytes),
            "stderr_bytes": len(stderr_bytes),
        }
    finally:
        os.close(stdout_fd)
        if stderr_fd >= 0:
            os.close(stderr_fd)
