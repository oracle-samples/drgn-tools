# drgn-tools

drgn-tools is a library of helpers for use with [drgn][drgn]. It contains
helpers with a slightly reduced scope than what drgn itself can contain.

The main target for these helpers is the Oracle UEK kernel. Helpers may contain
code that assumes a UEK configuration and UEK architectures. This makes a lower
bar for acceptance than drgn, where helpers should be as configuration and
architecture agnostic as possible. In general, helpers should be contributed to
drgn itself, unless there is an Oracle UEK-specific reason to keep them here.

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

## Getting Started

Requires Python 3.6 or later, and an Linux system (preferably Oracle Linux 8 or
later). For this guide, we'll assume you have a core dump (vmcore).

1. Install Drgn, if you haven't already: `pip install drgn`. Alternatively, `yum
   install drgn`, or use your system's package manager, if appropriate.
2. Clone the repository: `git clone
   https://github.com/oracle-samples/drgn-tools`

That's it! See below for ways to use drgn-tools.

## Documentation

You can find documentation for the helpers, as well as contributing guide and
guide to using our tools, [here](https://oracle-samples.github.io/drgn-tools/).

## Examples

One of the benefits of using drgn-tools, in addition to the added UEK-specific
helpers, is the ability to fetch debuginfo directly from the Oracle debuginfo
Yum server. To enable this, you should put the following contents in
`~/.config/drgn_tools.ini`:

``` ini
[debuginfo]
fetchers = OracleLinuxYumFetcher
```

With that, you can use the drgn-tools CLI with:

``` sh
python -m drgn_tools.cli VMCORE
```

To run it against the running kernel, use:

``` sh
python -m drgn_tools.cli /proc/kcore
```

Use the drgn-tools Corelens system (which outputs a range of information from
several diagnostic systems):

``` sh
python -m drgn_tools.corelens VMCORE
```

## Help

If you're having trouble using drgn-tools or its helpers, please create a Github
issue, and we'll try to help as best we can.

For customers having difficulties diagnosing issues with Oracle Linux or UEK,
please use My Oracle Support to create a request to engage our support team.

## Contributing

Drgn-tools welcomes contributions. However, when it comes to helpers, we believe
in an upstream-first policy. Helper functions ought to be contributed to
[drgn][drgn] wherever possible. In the case that code can't be contributed to
Drgn because it is specific to UEK configurations or architectures, we will
gladly accept it. Please see [CONTRIBUTING.md][] for details on contributing.

## Security

Please consult the [security guide](./SECURITY.md) for our responsible security
vulnerability disclosure process.

## License

Copyright (c) 2023 Oracle and/or its affiliates.

Released under the Universal Permissive License v1.0 as shown at
<https://oss.oracle.com/licenses/upl/>.

[drgn]: https://drgn.readthedocs.io
[doc]: https://oracle-samples.github.io/drgn-tools/
