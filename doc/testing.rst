Contributing: Testing
=====================

One of the most difficult things about making reliable kernel helpers is testing
them. It is important that our helpers work reliably on different kernel
versions: in particular, all supported versions of Oracle UEK.  Manually testing
these things, and watching for regressions, would be nearly impossible. So, we
have automated tests, located in the ``tests`` directory.  Each helper should
have a few tests associated with it, that should exercise all the major
functionality.

Test Targets
------------

The tests need a kernel to run on: either a live kernel, or a vmcore. Sometimes,
there are specific hardware requirements for a helper, since it deals with a
particular device driver or subsystem. Our current testing framework has three
targets, which fill different niches.

1. Lite Virtual Machine (litevm) tests. These can run on your local machine, or
   on Github Actions. The tests run against a live UEK kernel, which has mounted
   the host's filesystem via 9P.

2. Heavy Virtual Machine (heavyvm) tests. These can also run on a local machine,
   but they require extensive setup and disk space. The heavyvm tests also run
   on Oracle internal CI.

3. Vmcore tests. These run directly on your machine, and they load a vmcore and
   its associated debuginfo in order to run tests against them. Vmcores are
   stored in a specific filesystem hierarchy within the ``testdata/vmcores``
   directory.

To learn more about each kind of test, and how to run them, you can read the
detailed documentation in the ``testing`` directory's Readme file. For most
helpers that are not hardware specific, you can write tests and run them with
the "litevm" runner. For more hardware specific tests, you can run them with the
"vmcore" runner.

Running Litevm Tests Locally
----------------------------

It is quite easy to run litevm tests locally. Use ``make litevm-test`` and the
necessary tools and RPMs will get setup and run. The tests will run across UEK
versions 5, 6, 7. You'll need to have the following tools available on your
system:

- Qemu
- Busybox
- ``rpm2cpio`` and the ``cpio`` command
- The package ``kmod`` (contains ``depmod`` command)
- Compression packages: ``bzip2`` and ``gzip``
- Ext4 utils: ``mkfs.ext4``

This will run against all supported Python versions which are found on your
system. The first run will take a while, as necessary RPMs are downloaded and
extracted within the ``testdata`` directories. Future runs will be quicker.

Running Vmcore Tests Locally
----------------------------

Vmcore tests require you to maintain a directory (normally ``testdata/vmcores``)
which contains core dumps and their associated debuginfo files. Each vmcore must
be stored in a subdirectory with a descriptive name. Within the subdirectory,
the files must be named as so:

- ``vmcore`` - the ELF or makedumpfile formatted core dump
- ``vmlinux`` - the debuginfo ELF file for the matching kernel version
- ``*.ko.debug`` - any debuginfo for modules, which will be loaded here.  If
  your core dump contains any "virtio" modules loaded, be sure to include the
  virtio module debuginfo in order to run the tests.

If you have data stored on in your local ``testdata/vmcores`` directory, then
running ``make vmcore-test`` will automatically run tests against them.

Please see the ``testing/README.md`` file for more detailed documentation on the
vmcore test runner. In particular, there is support for uploading and
downloading the vmcores stored in your directory to a shared OCI Object Storage
bucket. This can enable teams to share vmcores for more thorough testing.

When sharing vmcores, please be aware that they can contain very sensitive data,
such as encryption keys, sensitive file contents, network buffers, addresses,
hostnames, etc. When creating a vmcore for testing & sharing, it's best to
create it outside of any internal environment, and access it without using any
shared passwords. Do not store credentials, API tokens, or cryptographic keys on
the machine. Due to the sensitive nature of vmcores, there is not yet a public
repository of shared vmcores for testing -- though we hope to create one soon.

Python Test Guidance
--------------------

Writing Tests: Basics
^^^^^^^^^^^^^^^^^^^^^

You can see some example tests in ``tests/test_mm.py``.  Generally, each file in
``drgn_tools`` should have a corresponding test file in ``tests``, but prefixed
with ``test_``.

Test code is written using the `pytest <https://docs.pytest.org/en/7.0.x/>`_
framework. Each test is a simple function whose name begins with ``test_``.
Within the test function, normally you call the "unit under test", and then make
various assertions about the result of the function call. For instance, to test
the above ``happy_birthday_message()`` function, you might write something like
this:

.. code-block:: python

   def test_happy_birthday() -> None:
       assert happy_birthday_message("Stephen", 1) == "happy 1st birthday, Stephen!"
       assert happy_birthday_message("Joe", 2) == "happy 2nd birthday, Joe!"
       assert happy_birthday_message("Sally", 3) == "happy 3rd birthday, Sally!"
       assert happy_birthday_message("Ben", 4) == "happy 4th birthday, Sally!"

The ``assert`` keyword is used to make these test assertion: you can use any
expression that results in a boolean.

Generally, you'll need some resources to run a test: for example, to test drgn
helpers, you need a :class:`drgn.Program` which has a linux kernel and debug
symbols loaded (either live, or vmcore). Rather than writing test code for this
yourself, you can simply use a pytest `"fixture"
<https://docs.pytest.org/en/7.0.x/how-to/fixtures.html#how-to-fixtures>`_. To do
this, you add an argument to your test function, named ``prog``:

.. code-block:: python

   def test_some_drgn_thing(prog: drgn.Program) -> None:
       ...

When your test is run, the pytest framework will look in ``tests/conftest.py``
to find a fixture named ``prog``, and it will use that code to create a Program
object. This way, your test can focus on testing functionality.


Writing Tests: High Level Goals
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Each helper function you create should have a test, though it may not need to be
the most strict. Testing goals are as follows:

1. Ensure that helpers work correctly
2. Ensure that helpers work on all UEK versions (i.e. they don't refer to struct
   fields that do not exist on older/newer versions)
3. Ensure that helpers don't break as the kernel (and drgn) updates

The first goal is the most difficult. You'll find that, for things like listing
internal data structures, it's difficult to get a "ground truth" to compare your
results against. The first strategy to deal with this is to attempt to read the
corresponding information out of userspace. For instance, when testing the
``totalram_pages`` function, I did this:

.. code-block:: python

    def test_totalram_pages(prog: drgn.Program) -> None:
        reported_pages = mm.totalram_pages(prog).value_()

        if prog.flags & drgn.ProgramFlags.IS_LIVE:
            # We're running live! Let's test it against
            # the value reported in /proc/meminfo.
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        mem_kb = int(line.split()[1])
                        break
                else:
                    assert False, "No memory size found"
            mem_bytes = mem_kb * 1024
            mem_pages = mem_bytes / getpagesize()

            assert mem_pages == reported_pages
        else:
            # We cannot directly confirm the memory value.
            # We've already verified that we can lookup the
            # value without error, now apply a few "smoke
            # tests" to verify it's not completely wonky.

            # At least 512 MiB of memory:
            assert reported_pages > (512 * 1024 * 1024) / getpagesize()
            # Less than 4 TiB of memory:
            assert reported_pages < (4 * 1024 * 1024 * 1024 * 1024) / getpagesize()

When running against a live kernel, the test can read ``/proc/meminfo`` and
verify the value directly. When running against a core dump, we fall back to a
less accurate behavior: simply verifying that the memory value falls within an
acceptable range.

While this approach isn't perfect, it does serve a purpose. It allows us to have
a test which still verifies goals #2 and #3. If the helper doesn't work on an
older UEK due to missing symbols or structure fields, we will find it, and same
with new and updated kernels or drgn versions.

For drgn-tools testing, we're trying not to make "perfect" the enemy of "good
enough". So long as we have a helper which is manually tested, and its automated
tests can at least satisfy #2 and #3, then we're likely to accept that and move
on.

Writing Tests: Specifying your Target
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

By default, all tests within the ``tests/`` directory are run against all
targets: live systems as well as vmcores. And for the most part, tests shouldn't
care too much about which target they run against. But unfortunately, you may
encounter issues where it matters. One example is the above memory test, where
you can use data from the system to make a more accurate test. However, another
example might be ``tests/test_block.py``, which runs fio in order to get block
device activity, so that the in-flight I/O system can print output.

In these cases, if you need to change your test behavior, you can check
:attr:`drgn.Program.flags` to customize the behavior. But if you need to fully
skip certain environments, you can annotate your test as follows:

.. code-block:: python

    import pytest

    @pytest.mark.skip_live
    def test_foobar(prog: drgn.Program) -> None:
       pass

This annotation is called a pytest "Mark". We have three marks for testing. The
first one, as shown here, is called ``skip_live`` and it ensures that the test
will not be run on live systems: that is, when ``/proc/kcore`` is being debugged
on the Gitlab CI. The other two marks allow you to select or skip vmcores that a
test runs on:

- ``vmcore("PATTERN")`` tells the test runner that the test should only run on
  vmcores which match PATTERN. The pattern is matched by :func:`fnmatch
  <fnmatch.fnmatch>`, which is essentially the syntax you use on the shell to
  match filenames. For example, ``vmcore("scsi-*")`` would make the test only
  run on vmcores whose name begins with ``scsi-``.

- ``skip_vmcore("PATTERN")`` tells the test runner that the test should be
  skipped on vmcores which match PATTERN.

So essentially these two marks are inverses: one lets you choose which vmcores
the test runs on, and the other lets you choose which the test should *not* run
on.

It's important to note that the ``vmcore()`` and ``skip_vmcore()`` marks don't
affect whether the test runs on live systems, the default is still yes, unless
you also use the mark ``skip_live``. So, if you only wanted to run a test on
exactly one vmcore named "special-vmcore" then you could do this:

.. code-block:: python

   @pytest.mark.skip_live
   @pytest.mark.vmcore("special-vmcore")
   def special_test_for_special_vmcore(prog: drgn.Program) -> None:
       pass

Please try to avoid using these annotations where possible. If you can make a
test support a target, even partially, then it's better. However, in some cases
it's out of your hands.
