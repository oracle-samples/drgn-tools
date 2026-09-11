# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""A tiny FUSE 3 filesystem for tests."""
import argparse
import ctypes
import errno
import os
import select
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Optional


_FILE_NAME = "file"
_FILE_PATH = b"/" + _FILE_NAME.encode()
_FILE_CONTENTS = b"test"
_STARTUP_TIMEOUT = 5.0
_SHUTDOWN_TIMEOUT = 5.0
_MNT_DETACH = 2


class _FuseArgs(ctypes.Structure):
    _fields_ = [
        ("argc", ctypes.c_int),
        ("argv", ctypes.POINTER(ctypes.c_char_p)),
        ("allocated", ctypes.c_int),
    ]


class _FuseVersion(ctypes.Structure):
    _fields_ = [
        ("major", ctypes.c_int),
        ("minor", ctypes.c_int),
        ("hotfix", ctypes.c_int),
        ("padding", ctypes.c_int),
    ]


class _FuseConfig(ctypes.Structure):
    # This is the FUSE 3.1 prefix through direct_io. New fields are appended.
    _fields_ = [
        ("set_gid", ctypes.c_int32),
        ("gid", ctypes.c_uint32),
        ("set_uid", ctypes.c_int32),
        ("uid", ctypes.c_uint32),
        ("set_mode", ctypes.c_int32),
        ("umask", ctypes.c_uint32),
        ("entry_timeout", ctypes.c_double),
        ("negative_timeout", ctypes.c_double),
        ("attr_timeout", ctypes.c_double),
        ("intr", ctypes.c_int32),
        ("intr_signal", ctypes.c_int32),
        ("remember", ctypes.c_int32),
        ("hard_remove", ctypes.c_int32),
        ("use_ino", ctypes.c_int32),
        ("readdir_ino", ctypes.c_int32),
        ("direct_io", ctypes.c_int32),
    ]


class _FuseOperations(ctypes.Structure):
    # The FUSE 3.1 prefix through init. All entries are function pointers.
    _fields_ = [
        (name, ctypes.c_void_p)
        for name in (
            "getattr",
            "readlink",
            "mknod",
            "mkdir",
            "unlink",
            "rmdir",
            "symlink",
            "rename",
            "link",
            "chmod",
            "chown",
            "truncate",
            "open",
            "read",
            "write",
            "statfs",
            "flush",
            "release",
            "fsync",
            "setxattr",
            "getxattr",
            "listxattr",
            "removexattr",
            "opendir",
            "readdir",
            "releasedir",
            "fsyncdir",
            "init",
        )
    ]


_Getattr = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p
)
_Open = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p)
_Read = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_long,
    ctypes.c_void_p,
)
_Write = _Read
_Filler = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_void_p,
    ctypes.c_long,
    ctypes.c_int,
)
_Readdir = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_void_p,
    _Filler,
    ctypes.c_long,
    ctypes.c_void_p,
    ctypes.c_int,
)
_Init = ctypes.CFUNCTYPE(
    ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(_FuseConfig)
)


def _load_fuse():
    fuse = ctypes.CDLL("libfuse3.so.3", use_errno=True)
    fuse.fuse_new.argtypes = [
        ctypes.POINTER(_FuseArgs),
        ctypes.POINTER(_FuseOperations),
        ctypes.c_size_t,
        ctypes.POINTER(_FuseVersion),
        ctypes.c_void_p,
    ]
    fuse.fuse_new.restype = ctypes.c_void_p
    fuse.fuse_mount.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    fuse.fuse_mount.restype = ctypes.c_int
    fuse.fuse_loop.argtypes = [ctypes.c_void_p]
    fuse.fuse_loop.restype = ctypes.c_int
    fuse.fuse_exit.argtypes = [ctypes.c_void_p]
    fuse.fuse_exit.restype = None
    fuse.fuse_unmount.argtypes = [ctypes.c_void_p]
    fuse.fuse_unmount.restype = None
    fuse.fuse_destroy.argtypes = [ctypes.c_void_p]
    fuse.fuse_destroy.restype = None
    return fuse


def _load_libc():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.lstat.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
    libc.lstat.restype = ctypes.c_int
    libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
    libc.umount2.restype = ctypes.c_int
    return libc


def _detach_mount(mountpoint: Path) -> None:
    libc = _load_libc()
    if libc.umount2(os.fsencode(str(mountpoint)), _MNT_DETACH) == 0:
        return
    if ctypes.get_errno() not in (errno.EINVAL, errno.ENOENT):
        raise OSError(ctypes.get_errno(), "umount2() failed")


def _run_server(
    mountpoint: Path, write_delay: float, ready_fd: int, control_fd: int
) -> int:
    fuse = _load_fuse()
    libc = _load_libc()
    stopped = threading.Event()
    active = threading.Event()
    mounted = False
    handle = None

    with tempfile.TemporaryDirectory(prefix="drgntools-fuse-backing-") as tmp:
        backing = Path(tmp)
        file_path = backing / _FILE_NAME
        file_path.write_bytes(_FILE_CONTENTS)

        @_Getattr
        def getattr(path, statbuf, fi):
            del fi
            if path == b"/":
                target = backing
            elif path == _FILE_PATH:
                target = file_path
            else:
                return -errno.ENOENT
            if libc.lstat(os.fsencode(str(target)), statbuf) == 0:
                return 0
            return -ctypes.get_errno()

        @_Open
        def open_(path, fi):
            del fi
            if path == _FILE_PATH:
                return 0
            return -errno.ENOENT

        @_Read
        def read(path, buf, size, offset, fi):
            del fi
            if path != _FILE_PATH:
                return -errno.ENOENT
            if offset < 0:
                return -errno.EINVAL
            contents = _FILE_CONTENTS[offset : offset + size]
            ctypes.memmove(buf, contents, len(contents))
            return len(contents)

        @_Write
        def write(path, buf, size, offset, fi):
            del buf, offset, fi
            if path != _FILE_PATH:
                return -errno.ENOENT
            if stopped.wait(write_delay):
                return -errno.EINTR
            return size

        @_Readdir
        def readdir(path, buf, filler, offset, fi, flags):
            del offset, fi, flags
            if path != b"/":
                return -errno.ENOENT
            for name in (b".", b"..", _FILE_NAME.encode()):
                if filler(buf, name, None, 0, 0):
                    break
            return 0

        @_Init
        def init(conn, config):
            del conn
            config.contents.direct_io = 1
            return None

        callbacks = [getattr, open_, read, write, readdir, init]
        operations = _FuseOperations()
        for name, callback in zip(
            ("getattr", "open", "read", "write", "readdir", "init"),
            callbacks,
        ):
            setattr(operations, name, ctypes.cast(callback, ctypes.c_void_p))

        argv = (ctypes.c_char_p * 1)(b"fuse_fixture")
        args = _FuseArgs(1, argv, 0)
        version = _FuseVersion(3, 1, 0, 0)
        handle = fuse.fuse_new(
            ctypes.byref(args),
            ctypes.byref(operations),
            ctypes.sizeof(operations),
            ctypes.byref(version),
            None,
        )
        if not handle:
            raise RuntimeError("fuse_new() failed")

        try:
            if fuse.fuse_mount(handle, os.fsencode(str(mountpoint))) != 0:
                raise OSError(ctypes.get_errno(), "fuse_mount() failed")
            mounted = True

            def stop_when_requested():
                try:
                    os.read(control_fd, 1)
                finally:
                    stopped.set()
                    if active.is_set():
                        fuse.fuse_exit(handle)

            thread = threading.Thread(target=stop_when_requested)
            thread.daemon = True
            active.set()
            thread.start()
            os.write(ready_fd, b"1")
            result = fuse.fuse_loop(handle)
            if stopped.is_set():
                return 0
            return result
        finally:
            active.clear()
            try:
                if mounted:
                    fuse.fuse_unmount(handle)
            finally:
                fuse.fuse_destroy(handle)
                os.close(ready_fd)
                os.close(control_fd)


class FuseFixture:
    """A mounted FUSE filesystem containing one file for use in tests."""

    def __init__(self, write_delay: float = 60.0):
        self.write_delay = write_delay
        self.file_path: Optional[Path] = None
        self.mountpoint: Optional[Path] = None
        self._control_fd: Optional[int] = None
        self._proc: Optional[subprocess.Popen] = None
        self._tempdir: Optional[tempfile.TemporaryDirectory] = None

    def __enter__(self):
        self._tempdir = tempfile.TemporaryDirectory(prefix="drgntools-fuse-")
        self.mountpoint = Path(self._tempdir.name)
        self.file_path = self.mountpoint / _FILE_NAME
        ready_fd, child_ready_fd = os.pipe()
        child_control_fd, self._control_fd = os.pipe()
        command = [
            sys.executable,
            str(Path(__file__).resolve()),
            "--server",
            str(self.mountpoint),
            str(self.write_delay),
            str(child_ready_fd),
            str(child_control_fd),
        ]
        self._proc = subprocess.Popen(
            command,
            close_fds=True,
            pass_fds=(child_ready_fd, child_control_fd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        os.close(child_ready_fd)
        os.close(child_control_fd)
        try:
            readable, _, _ = select.select(
                [ready_fd], [], [], _STARTUP_TIMEOUT
            )
            if not readable or os.read(ready_fd, 1) != b"1":
                self.close()
                raise RuntimeError("FUSE fixture failed to mount")
            return self
        except BaseException:
            self.close()
            raise
        finally:
            os.close(ready_fd)

    def __exit__(self, exc_type, exc_value, traceback):
        del exc_type, exc_value, traceback
        self.close()

    def close(self) -> None:
        proc = None
        if self._control_fd is not None:
            os.close(self._control_fd)
            self._control_fd = None
        if self._proc is not None:
            proc = self._proc
            try:
                proc.wait(_SHUTDOWN_TIMEOUT)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            self._proc = None
        if self._tempdir is not None:
            _detach_mount(Path(self._tempdir.name))
            self._tempdir.cleanup()
            self._tempdir = None
        self.file_path = None
        self.mountpoint = None


def _parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", action="store_true")
    parser.add_argument("mountpoint", type=Path)
    parser.add_argument("write_delay", type=float)
    parser.add_argument("ready_fd", type=int)
    parser.add_argument("control_fd", type=int)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    if not args.server:
        raise SystemExit("--server is required")
    sys.exit(
        _run_server(
            args.mountpoint, args.write_delay, args.ready_fd, args.control_fd
        )
    )


if __name__ == "__main__":
    main()
