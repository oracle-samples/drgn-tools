Testing
=======

This directory contains (substantial) machinery necessary for running drgn-tools
tests. There are three distinct testing systems present here, each of which
satisfy specific goals:

1. The "litevm" testing system uses Qemu to boot a UEK kernel, and then mounts
   the host filesystem using 9p. The test suite can be executed directly from
   the host filesystem.
2. The "heavyvm" testing system contains fully automated infrastructure that can
   download Oracle Linux ISOs, install them inside a virtual machine, and then
   install the UEK kernel and debuginfo. Tests can then be run by copying the
   necessary files and executing them via SSH.
3. The "vmcore" testing system allows you to maintain a library of core dumps
   and their correpsonding debuginfo, and execute the drgn-tools test suite on
   each. It also comes with upload and download systems that allow users to
   share the vmcores on OCI object storage.

Each test environment has benefits and drawbacks:

- litevm
    - Quickest to set up and requires the least disk space.
    - Easiest to run in CI systems like Github Actions due to low overhead.
    - Automatically tests the latest UEK releases as they come out.
    - Since it uses the host filesystem, it may not detect compatibility issues
      with Drgn on Oracle Linux.
    - Also, since it is VM-based, there are few opportunities for testing
      helpers that relate to specific hardware drivers, or configurations not
      found on your development / CI machine.
    - Since litevm depends on 9p, it's not fully compatible with older UEK
      versions.
- "heavyvm"
    - Having a full OL userspace means we can detect compatibility issues: we
      are testing the full system, integration-test style.
    - Allows us to run tests on older UEK kernels such as UEK4.
    - Can keep up with the latest UEK versions, but disk images need to be
      rebuilt.
    - Requires much data to be downloaded and much more disk space to store the
      disk images.
    - Still limited in terms of hardware & software configurations.
    - Difficult or impossible to run on public CI systems without having a
      large, persistent storage location for disk images.
- "vmcore"
    - Allows testing on a broad variety of hardware and software configurations.
    - Also fairly lightweight, so long as the vmcore is generated using
      aggressive makedumpfile options.
    - Vmcores can contain sensitive data, so great care needs to be used when
      generating vmcores that will be publicly released. As a result, we do not
      yet provide any testing vmcores, though we hope to do this in the future.

litevm
------

### Overview

The litevm system uses the latest UEK kernel from the Oracle Linux yum
repositories. It downloads the necessary RPMs and extracts them. In order to
boot into the host filesystem, an initial ramdisk must be created which contains
the necessary kernel modules. (9p is not built-in to UEK kernels). The litevm
builds the initrd using busybox, and finally boots into the new system to
execute a user command.

Dependencies:

- Qemu
- Busybox
- Rpm tools (`rpm2cpio`, `cpio`)
- Kmod package (`depmod`)
- Compression tools: `bzip2`, `gzip`
- Ext4 utils (`mkfs.ext4`)

Test data storage:

- `testdata/yumcache`: contains downloaded yum repositories and kernel RPMs
- `testdata/rpmextract`: holds the contents of the extracted RPMs

Oddities:

- On UEK5, the `CONFIG_9P_FS` configuration is disabled. Thankfully, it is
  simple enough to build the module out-of-tree. The patch and module for this
  are provided in `testing/litevm/mod`.

### Usage

To download the latest RPMs for each test kernel:

    python -m testing.litevm.rpm

The above is not strictly necessary (the RPMs will be downloaded by the next
step if not present). However, it is useful to have it as a separate step for
CI.

To run commands on the lite VMs:

    python -m testing.litevm.vm [command ...]

Please see the `--help` output of each command for full details.

heavyvm
-------

### Overview

The heavyvm system contains several scripts to maintain disk images containing
full Oracle Linux userspace and UEK kernel.

- `testing/heavyvm/images.py` is a configuration file, which lists out the
  different configurations which we build for: OL7-9, UEK4-7.
- `testing/heavyvm/imgbuild.py` is a script for automating the creation of qemu
  disk images directly from the ISO installers. This is used periodically to
  create fresh VM images with the latest package and kernel versions.
- `testing/heavyvm/qemu.py` contains helpers for interacting with Qemu, and a
  quick command line tool for easily running a VM.
- `testing/heavyvm/runner.py` is a script for orchestrating all the VMs:
  bringing them up, distributing drgn-tools code to them, running test commands,
  and shutting them down.

Requirements:

- Qemu, and the qemu disk utils (see oddities for Oracle Linux info)
- `wget`
- `7z` from the `p7zip-plugins` package
- `mtools` package (FAT filesystem in userspace)
- Quite a bit of time to build the VMs, and disk space to store them

Test data:

- `testdata/iso` - downoaded Oracle Linux ISO files
- `testdata/images` - built disk images
- `testdata/heavy-vminfo` - directory to store serial connection files

Oddities:

- All VMs are created with the root password "password", and they enable root
  password login via SSH. These VMs are insecure by default, because they are
  **only** intended to be used for the purpose of running these tests. Please
  keep this in mind and **never** use these VMs for other purposes.
- To run the tests on an Oracle Linux machine, you'll need to compile Qemu from
  source, and use the `$PATH` environment variable to ensure your compiled
  version is used ahead of the system one. The packaged version doesn't include
  all the necessary features enabled at compile time. As far as I can tell, this
  step is unnecessary on Ubuntu.

### Usage

Prior to running any tests, you must first build the VM images. This is fully
automated: it starts with ISO files and automatically builds from there. You
must have an internet connection, since the installer pulls the latest packages
from Yum. To use the image builder:

    python -m testing.heavyvm.imgbuild

You can customize the storage locations, and select which images are built,
using various command line flags -- see `--help` output for more.

Once the images are built, if you'd like to explore them, then you can boot one
and run serial commands via the Qemu monitor. The test system avoids modifying
the disk images by creating an "overlay" disk, so you don't need to worry about
impacting the state of the VM for later tests.

    python -m testing.heavyvm.qemu path/to/disk.img

Finally, to run the tests within the VMs, you'll need to first create a git
archive of the current source tree, and specify that when you run the test.

    git archive HEAD -o archive.tar.gz
    python -m testing.heavyvm.runner --tarball archive.tar.gz

Again, you can select which image you run tests on, as well as other options,
accessible from the `--help` output.

vmcore
------

### Overview

The vmcore testing system allows you to maintain a library of vmcores for
running tests. The vmcore library should be stored at `testdata/vmcores`. Each
core should get a subdirectory with a descriptive name. The subdirectory name
will serve as the identifier for the vmcore. The contents of the directory
should be just like the following:

- `vmcore` - the ELF or makedumpfile formatted core dump
- `vmlinux` - the debuginfo ELF file for the matching kernel version
- `*.ko.debug` - any debuginfo for modules, which will be loaded here.
  - If your core dump contains any "virtio" modules loaded, be sure to include
    the virtio module debuginfo in order to run the tests.

The vmcore system provides the ability to upload and download vmcores to an OCI
object storage bucket. You can configure the location by the following
environment variables:

- `VMCORE_NAMESPACE` - this is usually the name of the tenancy where your block
  storage bucket resides
- `VMCORE_BUCKET` - the bucket name
- `VMCORE_PREFIX` - the prefix (similar to a directory) where vmcores are stored

Please note that it is not required to use the upload/download system. You can
manage your vmcores locally without needing to use OCI object storage.

### Usage

Assuming you have created the necessary directories and files, you can use the
following to run tests:

    python -m testing.vmcore test

If you've configured OCI and your `VMCORE_*` variables, then you can use the
uploader to upload a specific vmcore, or download all vmcores.

    python -m testing.vmcore upload --upload-core $name
    python -m testing.vmcore downoad

Vmcores
-------

Generate vmcore for md helpers:
- create 3 md devices, raid0/1/5
- create xfs on it and mount
- drop page caches
- run fio script to trigger io load on them
- trigger system crash after io load starts
