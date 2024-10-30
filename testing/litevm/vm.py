# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
UEK VM Logic - launches a qemu VM with unmodified UEK kernel
"""
import argparse
import contextlib
import fnmatch
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from itertools import combinations
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Dict
from typing import Iterable
from typing import Iterator
from typing import List
from typing import Optional

from testing.litevm.rpm import extract_rpms
from testing.litevm.rpm import TEST_KERNELS
from testing.litevm.rpm import TestKernel
from testing.util import BASE_DIR
from testing.util import ci_section


INITRD_DIRS = [
    "bin",
    "sbin",
    "etc",
    "proc",
    "sys",
    "tmp",
    "usr/bin",
    "usr/sbin",
]

INITRD_MODULES = [
    "9p",
    "9pnet_virtio",
    "overlay",
    "virtio_input",
    "virtio_pci",
]

INIT_SCRIPT = """#!/bin/sh
set -x

cleanup() {{
    if [ "$?" -ne 0 ]; then
        echo DRGN_TOOLS: FAILURE
    fi
    poweroff -f
}}
trap cleanup EXIT

mount -t proc none /proc
mount -t tmpfs tmpfs /tmp

modprobe -a {modules} || exit 1

mkdir /tmp/upper /tmp/lower /tmp/workdir /tmp/merged
mkdir /tmp/upper/dev /tmp/upper/etc /tmp/upper/mnt
mkdir -m 555 /tmp/upper/proc /tmp/upper/sys
mkdir -m 1777 /tmp/upper/tmp

mount -t 9p -o ro,trans=virtio,cache=loose,msize=1048576 root9p /tmp/lower

mount -t overlay \
      -o lowerdir=/tmp/lower,upperdir=/tmp/upper,workdir=/tmp/workdir \
      overlay /tmp/merged

mount -t proc none /tmp/merged/proc
mount -t sysfs sys /tmp/merged/sys
mount -t tmpfs tmpfs /tmp/merged/tmp
mount -t devtmpfs dev /tmp/merged/dev

exec switch_root /tmp/merged /bin/sh {init_post}
"""

INIT_POST_SCRIPT = """#!/bin/sh
set -x

export PATH=/sbin:/usr/sbin:/bin:/usr/bin

cleanup() {{
    if [ "$?" -ne 0 ]; then
        echo DRGN_TOOLS: FAILURE
    fi
    poweroff -f
}}
trap cleanup EXIT

mkdir -p /lib/modules/{release}
mount --bind {extract}/lib/modules/{release} /lib/modules/{release}

mkdir -p /usr/lib/debug/lib/modules/{release}
mount --bind {extract}/usr/lib/debug/lib/modules/{release} \
             /usr/lib/debug/lib/modules/{release}

modprobe virtio-blk
mkfs -t ext4 /dev/vda
mount /dev/vda /mnt
export DRGNTOOLS_BLOCK_TEST_DIR=/mnt

cd {pwd}
{command}
cleanup
"""


def topological_sort(
    g: Dict[str, List[str]], start: Optional[Iterable[str]] = None
) -> List[str]:
    """
    A pretty basic recursive topological sort

    We need a topological sort so we can instruct modprobe to load the modules
    in the correct order. I swear, it should be able to figure this out itself,
    but without this, the boot fails. Topological sort gets super annoying to do
    iteratively, so this is implemented recursively. If we are dealing with
    enough modules to reach recursion limit issues, then something is very
    wrong.
    """
    order = []
    seen = set()

    def r(start: str):
        if start in seen:
            return
        seen.add(start)
        for descendent in g[start]:
            r(descendent)
        order.append(start)

    if not start:
        start = g.keys()

    for s in start:
        r(s)
    return order


def read_modules_dep(path: Path) -> Dict[str, List[str]]:
    modules_dep = {}
    with path.open() as f:
        for line in f.readlines():
            key, value = line.split(":")
            modules_dep[key.strip()] = value.split()
    return modules_dep


def module_name(mod: str) -> str:
    return mod.split("/")[-1].split(".")[0]


def write_modules_dep(
    out_file: Path,
    subset: List[str],
    full_modules: Dict[str, List[str]],
) -> None:
    with out_file.open("wt") as f:
        for mod in subset:
            deps = full_modules[mod]
            line = f"{mod}:"
            if deps:
                line += " " + " ".join(deps)
            f.write(line + "\n")


def copy_modules(release: str, root_dir: Path, initrd_dir: Path) -> List[str]:
    # Now we must get all necessary modules to support mounting the host
    # filesystem with 9p and an overlay. To do this, we need to start with
    # the basic list of required modules, get the depnedencies via the
    # modules.dep file, come up with an orderig for them to be loaded,
    # and copy them all in.
    initrd_modules_dir = initrd_dir / "lib/modules" / release
    root_modules_dir = root_dir / "lib/modules" / release

    full_modules = read_modules_dep(root_modules_dir / "modules.dep")
    mod_to_path = {module_name(mod): mod for mod in full_modules.keys()}
    initrd_module_paths = []
    for mod in INITRD_MODULES:
        if mod in mod_to_path:
            initrd_module_paths.append(mod_to_path[mod])
    needed_paths = topological_sort(full_modules, initrd_module_paths)

    initrd_modules_dir.mkdir(parents=True)
    for mod_path_str in needed_paths:
        dst = initrd_modules_dir / mod_path_str
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(root_modules_dir / mod_path_str, dst)

    write_modules_dep(
        initrd_modules_dir / "modules.dep",
        needed_paths,
        full_modules,
    )
    return needed_paths


def create_initrd(
    release: str, root_dir: Path, command: str = "/bin/sh"
) -> Path:
    """
    Given a kernel version, and the extracted RPMs, generate an initrd

    The initrd here must be usable to boot within Qemu and get mount the host
    filesystem using 9p, and also with an overlay that allows us to make
    modifications to the filesystem with no impact on the host. Once mounted,
    the initrd should switch root and execute the desired command.
    """
    with TemporaryDirectory() as tempdir:
        # First we create the initrd skeleton
        td = Path(tempdir)
        for path in INITRD_DIRS:
            (td / path).mkdir(parents=True, exist_ok=True)

        modules = copy_modules(release, root_dir, td)
        modules = [module_name(m) for m in modules]

        # Copy in the init script
        init = td / "init"
        init_post = root_dir / "init_post"
        with init.open("wt") as f:
            f.write(
                INIT_SCRIPT.format(
                    command=command,
                    modules=" ".join(modules),
                    init_post=shlex.quote(str(init_post)),
                )
            )
        init.chmod(0o755)

        # Create the "init_post" script in the root dir
        with init_post.open("wt") as f:
            f.write(
                INIT_POST_SCRIPT.format(
                    command=command,
                    release=release,
                    extract=shlex.quote(str(root_dir)),
                    pwd=shlex.quote(str(Path.cwd())),
                )
            )

        # Now, install busybox.
        busybox = td / "bin/busybox"
        host_busybox = shutil.which("busybox")
        if not host_busybox:
            raise Exception("Unable to locate busybox, please install it")
        shutil.copy(host_busybox, td / "bin/busybox")
        subprocess.run(
            [str(busybox), "--install", str(td / "bin")],
            check=True,
        )

        # And now, we are ready to create the CPIO image.
        # Could this be done more in Python? Yes. But honestly, this
        # pipeline is good enough and is used by lots of folks.
        initrd = root_dir / f"boot/initramfs-{release}.img"
        initrd.parent.mkdir(parents=True, exist_ok=True)
        with initrd.open("w") as f:
            subprocess.run(
                "find . -print0 "
                "| cpio --null --format=newc --create --quiet "
                "| gzip --best --no-name",
                cwd=td,
                check=True,
                shell=True,
                stdout=f.fileno(),
            )
        return initrd


@contextlib.contextmanager
def create_block_image(size_mb: int = 200) -> Iterator[Path]:
    with TemporaryDirectory() as tempdir:
        td = Path(tempdir)
        disk_image = td / "disk.img"
        with disk_image.open("wb") as f:
            f.truncate(size_mb * 1024 * 1024)
        yield disk_image


def find_vmlinuz(release: str, root_dir: Path) -> Path:
    path_in_modules = root_dir / "lib/modules" / release / "vmlinuz"
    if path_in_modules.is_file():
        return path_in_modules
    return root_dir / f"boot/vmlinuz-{release}"


def run_vm(kernel: TestKernel, extract_dir: Path, commands: List[List[str]]):
    release = kernel.latest_release()
    extract_dir = extract_dir / release
    if not extract_dir.is_dir():
        extract_rpms(kernel.get_rpms(), extract_dir, kernel)

    script = ""
    if commands:
        for argv in commands:
            command_str = shlex.quote(
                " ".join(shlex.quote(arg) for arg in argv)
            )
            script += f"/bin/sh -c {command_str}\n"
    else:
        script = "/bin/sh"
    initrd = create_initrd(release, extract_dir, command=script)
    vmlinuz = find_vmlinuz(release, extract_dir)
    with create_block_image() as block_img_path, tempfile.NamedTemporaryFile() as tf:
        qemu = f"qemu-system-{kernel.arch}"
        if os.access("/dev/kvm", os.R_OK | os.W_OK):
            args = [qemu, "-cpu", "host", "--enable-kvm"]
        else:
            args = [qemu]
        subprocess.run(
            args
            + [
                "-kernel",
                str(vmlinuz),
                "-initrd",
                str(initrd),
                "-nographic",
                "-m",
                "2G",
                "-drive",
                f"file={block_img_path},if=virtio,driver=raw",
                "-virtfs",
                "local,id=root,path=/,mount_tag=root9p,readonly=on,security_model=none,multidevs=remap",
                "-append",
                "console=ttyS0",
                "-chardev",
                f"stdio,id=char0,logfile={tf.name},mux=on,signal=off",
                "-serial",
                "chardev:char0",
                "-mon",
                "chardev=char0",
            ],
            check=True,
        )
        output = tf.read()
    if b"DRGN_TOOLS: FAILURE" in output:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Lite VM Runner")
    parser.add_argument(
        "--extract-dir",
        type=Path,
        default=BASE_DIR / "rpmextract",
        help="Directory to store extracted RPM data",
    )
    parser.add_argument(
        "--yum-cache-dir",
        type=Path,
        default=BASE_DIR / "yumcache",
        help="Directory to store Yum Repo and RPM data",
    )
    parser.add_argument(
        "--kernel",
        help="Match against the given kernel (eg *uek6*)",
    )
    parser.add_argument(
        "--with-ctf",
        action="store_true",
        help="Run tests with CTF in addition to DWARF",
    )
    parser.add_argument(
        "--delete-after-test",
        action="store_true",
        help="Delete RPM cache and extract directory after test",
    )
    parser.add_argument(
        "command",
        nargs="*",
        help="Command to run on each vm (leave empty for default: test)",
    )
    args = parser.parse_args()
    if args.command:
        cmd = args.command
    else:
        cmd = [
            sys.executable,
            "-m",
            "pytest",
            "tests",
            "-rP",
        ]
    ctf_enabled = [False]
    if args.ctf:
        ctf_enabled.append(True)
    for k, ctf in combinations(TEST_KERNELS, ctf_enabled):
        k.cache_dir = args.yum_cache_dir
        if args.kernel and not fnmatch.fnmatch(k.slug(), args.kernel):
            continue
        if ctf:
            section_name = f"uek{k.uek_ver}_CTF"
            section_text = f"Run tests on UEK{k.uek_ver} with CTF"
            # add the CTF argument here
            run_cmd = cmd + ["--ctf"]
        else:
            section_name = f"uek{k.uek_ver}"
            section_text = f"Run tests on UEK{k.uek_ver}"
            run_cmd = cmd
        with ci_section(section_name, section_text):
            release = k.latest_release()
            extract_dir = args.extract_dir / release
            run_vm(k, args.extract_dir, [run_cmd])
            if args.delete_after_test:
                shutil.rmtree(extract_dir)
                k.delete_cache()


if __name__ == "__main__":
    main()
