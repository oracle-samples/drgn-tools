drgn-tools
==========

drgn-tools is a library of helpers for use with [drgn][drgn]. It contains
helpers with a slightly reduced scope than what drgn itself can contain.

The main target for these helpers is the Oracle UEK kernel. Helpers may contain
code that assumes a UEK configuration and UEK architectures. This makes a lower
bar for acceptance than Drgn, where helpers should be as configuration and
architecture agnostic as possible.

In addition to the helper functions, drgn-tools contains some helper utilities
that we find useful:

1. The `DRGN` script which can automatically download, extract, and load
   debuginfo for UEK kernels.
2. The `corelens` tool, which contains a library of modules that can extract
   information from a live kernel or vmcore, and write it to a sosreport-style
   directory for later analysis.

Please note, each drgn-tools version is only supported with a corresponding
version of Drgn.

See the [documentation][doc] for more information on how to use these tools and
how to contribute to them.

Getting Started
---------------

Requires Python 3.6 or later, and an Linux system (preferably Oracle Linux 8 or
later). For this guide, we'll assume you have a core dump (vmcore).

1. Install Drgn, if you haven't already: `pip install drgn`. Alternatively, `yum
   install drgn`, or use your system's package manager, if appropriate.
2. Clone the repository: `git clone
   https://github.com/oracle-samples/drgn-tools`

That's it! See below for ways to use drgn-tools.

Usage Examples
--------------

Use the drgn-tools CLI (which uses its own debuginfo fetching logic) with:

``` sh
python -m drgn_tools.cli VMCORE
```

Use the drgn-tools Corelens system (which outputs a range of information from
several diagnostic systems):

``` sh
python -m drgn_tools.corelens VMCORE
```

How to Contribute
-----------------

Drgn-tools welcomes contributions. However, when it comes to helpers, we believe
in an upstream-first policy. Helper functions ought to be contributed to
[drgn][drgn] wherever possible. In the case that code can't be contributed to
Drgn because it is specific to UEK configurations or architectures, we will
gladly accept it. Please see [CONTRIBUTING.md][] for details on contributing.

[drgn]: https://drgn.readthedocs.io
[doc]: https://oracle-samples.github.io/drgn-tools/
