Testing
=======

This directory contains (substantial) machinery necessary for running drgn-tools
tests. We have two main types of tests:

- VM tests, where we boot Oracle Linux kernels & userspace, and run tests
  against the booted kernel. We also build & load a kernel module as test data.
- Vmcore tests, where we run tests against kernel core dump files. These can be
  run on the host filesystem, or run in the Oracle Linux rootfs from the VM test
  system.


System Requirements
-------------------

The following are the system requirements for running both kinds of tests.
Oracle Linux is the expected platform, although it is likely that Fedora and
other distros should work fine. The ideal system is a bare-metal one with at
least 8 CPU cores and ample memory (ideally, 4 GiB per-core). In addition,
around 40 GiB of free disk space should be available if you are doing VM tests,
and an additional 100 GiB would be necessary to store the various vmcores
(assuming you have access to them). Finally, a speedy Internet connection is
helpful in creating the rootfs, as well as downloading kernels & vmcores.

For Oracle Linux 9:

```sh
dnf config-manager --enable ol9_addons
dnf config-manager --enable ol9_kvm_utils
dnf config-manager --enable ol9_codeready_builder
dnf config-manager --enable ol9_developer_EPEL
dnf install -y git drgn qemu-kvm podman virtiofsd \
               cpio gzip bzip2 zstd busybox
```

For Oracle Linux 10:

```sh
dnf config-manager --enable ol10_addons
dnf config-manager --enable ol10_kvm_utils
dnf config-manager --enable ol10_codeready_builder
# Adjust as necessary for the currently available EPEL point release:
dnf config-manager --enable ol10_u1_developer_EPEL
# The fixed busybox RPM should become available in ol10_u2_developer_EPEL
dnf install -y git drgn qemu-kvm podman virtiofsd \
               cpio gzip bzip2 zstd \
               https://kojipkgs.fedoraproject.org//packages/busybox/1.37.0/4.el10_2/x86_64/busybox-1.37.0-4.el10_2.x86_64.rpm
```


Running VM Tests
----------------

To run all VM tests:

```sh
python -m testing.vm.runner [-j PROCESSES]
```

For each kernel target (see `testing/config.py`) this will build the OL rootfs
if necessary, download and extract the latest kernel & debuginfo, build a test
kernel module, boot the virtual machine, and run tests with DWARF and CTF
debuginfo. After the first run, subsequent runs will be much faster, because
they can make use of the already-built rootfs, and already-downloaded kernels.
The `-j` option will parallelize whichever operations can be shared in order to
accelerate the tests.

You can also pass through arguments to the underlying unittest runner (see "Test
Runner" below), for example to select a particular subset of tests. This can
help run your tests much faster:

```sh
python -m testing.vm.runner -- tests/test_my_module.py
```

The runner's help output (`--help`) can provide guidance on running against
specific kernels, python versions, or debuginfo kinds, as well as controlling
output levels. For advanced use, you may also want to see the sections below
about running commands within the VM itself, and directly running the test
runner.


Running Vmcore Tests
--------------------

To run all vmcore tests (with both CTF & DWARF debuginfo):

```sh
python -m testing.vmcore.runner [-j PROCESSES]
```

This runs tests against all vmcores in the test directory (see "Test Directory
Layout" below). It's recommended to use the parallel option, as the serial
execution time can be quite long if you have a lot of vmcores. However, note
that memory usage can get quite high with high parallelism.

It is also possible to run vmcore tests within the same Oracle Linux rootfs used
by the VM tests. This will ensure that the specific drgn RPM and system
libraries for each OL version are exercised:

```sh

python -m testing.vmcore.runner --ol VERSION [-j PROCESSES]
```

Finally, just like the VM runner, you can also pass through arguments to the
unittest runner, enabling you to select particular tests:

```sh
python -m testing.vmcore.runner -j8 -- tests/test_my_module.py
```

If you would like to run tests against a single vmcore and see all test output,
the simplest way is to directly run the test runner, as seen in the next
section.


Test Runner
-----------

Both the vm and the vmcore test runners are simply tools that end up calling the
test runner, `testing/unittest_runner.py`. You can directly call it yourself for
more control when running a specific test scenario. It takes arguments that
configure what sort of target the tests run against.

To run tests against a live kernel (with or without CTF):

```sh
python -m testing.unittest_runner [--ctf]
```

To run tests against a vmcore (with or without CTF):

```sh
python -m testing.unittest_runner --vmcore core-name
```

You can specify test files or modules as positional arguments:

```sh
python -m testing.unittest_runner tests/test_mymodule.py
```


VM Interactive Mode
-------------------

If you would like to do interactive diagnostics within the test VM environment,
you can do so using the script below:

```sh
python -m testing.vm.boot KERNEL [command]
```

The help output will show you the available kernels. By default, the command
will be an interactive bash session.


Rootfs Management
-----------------

The rootfs contains a userspace environment for a specific Oracle Linux version.
It is typically built automatically by the `vm` test runner prior to a test.
However you can manually build/rebuild it, which is useful to test against
specific RPMs (e.g. unreleased drgn versions). You can also launch a shell
within the rootfs, which can be useful for testing and development.

To build (or rebuild) all rootfses:

```sh
python -m testing.rootfs [--rebuild] [8 9 10]
```

The rebuild flag will cause already existing rootfses to be rebuilt. By default
all rootfses are rebuilt but specific OL versions can be specified on the CLI.

To run a command within the rootfs:

```sh
python -m testing.chroot testdata/rootfs/ol8-x86_64 -- bash -l
```

Though `bash -l` is a good command for an interactive session, any command can
be used (e.g. a drgn command).


Vmcore Management
-----------------

The vmcores are found in the `vmcores` test directory (see below).
The official set of vmcores is stored in a private object storage bucket. If you
have the pre-authenticated URL in your environment (`OCI_PAR_URL`) you can use
the following to download (or update) them:

```sh
python -m testing.vmcore.manage download
```

If you have a new vmcore, and you have a `OCI_PAR_URL` with write permissions,
you can upload a specific core:

```sh
python -m testing.vmcore.manage upload [--upload-all | --upload-core NAME]
```


Test Directory Layout
---------------------

To run the test system, we have a "test directory" that contains vmcores, root
filesystem images, downloaded kernels and debuginfo, and all the other necessary
components for testing. Normally it is named `testdata` in the root of the git
repository, but this can be customized at runtime.

```
testdata/

    # Storage of vmcores and their debuginfo for testing:
    vmcores/

        # Each directory is named
        $VMCORENAME/
            vmcore
            UTS_RELEASE
            vmlinux.ctfa
            vmlinux
            module.ko.debug
            ...

    # Root filesystems for running VM & vmcore tests
    rootfs/
        ol8-x86_64/
        ol9-x86_64/
        ol10-x86_64/

    # Storage of cached data for running VM tests
    vm/

        # Each VM target has a named directory
        ol10-uek8-x86_64/

            rpmdb/         # cached yum database
            kernel/        # artifacts by kernel version
                $VERSION/
                    kmod/  # build dir for kernel mod
                    root/  # RPM extraction directory

    # Test log directory
    logs/
        vm-test-ol10-uek8-x86_64-dwarf-python3.log
        vmcore-NAME-dwarf-hostfs-python3.log
```
