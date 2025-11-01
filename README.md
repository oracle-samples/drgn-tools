# drgn-tools

drgn-tools is Oracle's set of helpers and tools based on [drgn][drgn], including
Corelens, our tool for generating summary reports of a vmcore or live system.

The main target for drgn-tools is the Oracle UEK kernel. Thus, it may assume
kernels with UEK configurations and architectures. This is different from drgn,
which aims to support a much broader set of configurations and architectures.
Where possible, we aim to contribute to drgn upstream first.

In addition to helper functions, drgn-tools contains some tools that we find
useful:

1. The `drgn_tools.cli` script which provides a CLI similar to drgn's, with our
   helpers imported.
2. The `corelens` tool (`drgn_tools.corelens`), which contains a library of
   modules that can extract information from a live kernel or vmcore, and write
   it to a sosreport-style directory for later analysis. You can learn more
   about Corelens in [this article][blog-corelens].

Drgn-tools also contains logic that can help automatically fetch & extract
Oracle Linux kernel debuginfo, as well as configure and load Compact Type Format
(CTF) for supported UEK kernels. This makes using tools like Corelens and the
CLI seamless on OL, frequently not even requiring installation of debuginfo
packages. You can learn more about CTF in [this article][blog-ctf].

## Getting Started

Oracle Linux users should consult the Oracle Linux Documentation section
entitled "Installing drgn-tools" for the most up-to-date instructions: [OL 8][],
[OL 9][], [OL 10][].  To summarize, enable the Add-ons channel, and then install
the `drgn-tools` package. For example:

``` sh
dnf config-manager --enable ol10_addons
dnf install drgn-tools
```

For other users, or those interested in running from source: Drgn-tools requires
Python 3.6 or later, and drgn 0.0.32 or later. These can be installed from your
OS package manager preferably, or via pip, uv, etc. Once installed, you can
clone `drgn-tools` with git and start running against your kernel.

## Documentation

Documentation for usage of drgn & drgn-tools can be found in the Oracle Linux
Documentation section entitled ["Debugging the Kernel with Drgn and
Corelens"][ol10doc].

You can find some automatically generated documentation of the helpers, as well
as contributing guide and guide to using our tools,
[here](https://oracle-samples.github.io/drgn-tools/). Please note that this site
is not always fully up-to-date, and content here reflects internal
implementation details not supported by Oracle.

## Examples

Use Corelens to generate a report of the running kernel. Output is written to a
directory named "output":

``` sh
corelens /proc/kcore -a -o output
```

The above command uses the Corelens binary installed to the system. If you have
cloned the drgn-tools source code, you could instead run this command from the
git repository root:

``` sh
python -m drgn_tools.corelens /proc/kcore -a -o output
```

One of the benefits of using drgn-tools, in addition to the added UEK-specific
helpers, is the ability to fetch debuginfo directly from the Oracle debuginfo
Yum server. Corelens and the drgn-tools CLI enable this automatically, but when
drgn-tools is installed, you can use it with drgn too:

``` sh
# Use CTF (on Oracle Linux with UEK)
drgn -c /proc/kcore --try-symbols-by=ctf

# Download and extract debuginfo RPMs for Oracle Linux
drgn -c /proc/kcore --try-symbols-by=ol-download
```

Downloaded debuginfo is stored in a directory `~/vmlinux_repo` by default. You
can configure this and many other aspects of debuginfo finding and loading in
`/etc/drgn_tools.ini` or `~/.config/drgn_tools.ini`.

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
gladly accept it. Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for details on
contributing.

## Security

Please consult the [security guide](./SECURITY.md) for our responsible security
vulnerability disclosure process.

## License

Copyright (c) 2023-2025 Oracle and/or its affiliates.

Released under the Universal Permissive License v1.0 as shown at
<https://oss.oracle.com/licenses/upl/>.

[drgn]: https://drgn.readthedocs.io
[doc]: https://oracle-samples.github.io/drgn-tools/
[OL 8]: https://docs.oracle.com/en/operating-systems/oracle-linux/8/drgn/installing_drgn_tools.html
[OL 9]: https://docs.oracle.com/en/operating-systems/oracle-linux/9/drgn/installing_drgn_tools.html
[OL 10]: https://docs.oracle.com/en/operating-systems/oracle-linux/10/drgn/installing_drgn_tools.html
[drgn plugin]:https://drgn.readthedocs.io/en/latest/advanced_usage.html#writing-plugins
[blog-corelens]: https://blogs.oracle.com/linux/corelens-a-microscope-for-your-vmcores
[blog-ctf]: https://blogs.oracle.com/linux/introducing-ctf-support-in-drgn-for-oracle-linux
[ol10doc]: https://docs.oracle.com/en/operating-systems/oracle-linux/10/drgn/about_drgn_and_corelens.html
