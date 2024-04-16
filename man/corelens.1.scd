CORELENS(1)

; Copyright (c) 2024, Oracle and/or its affiliates.
; Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/

# NAME

corelens - extract diagnostic info from the running kernel or core dump

# SYNOPSIS

Generate a corelens report:

	*corelens* [-o OUT] _VMCORE_ [-a | -A]

Run specified modules:

	*corelens* [-o OUT] _VMCORE_ [-M MODULE [options] [-M MODULE ...]]

Get help:

	*corelens -h*

	*corelens -L*

	*corelens -M* _MODULE_ *-h*

# DESCRIPTION

Corelens is a tool which can extract diagnostic information from the Linux
kernel image specified by _VMCORE_. To extract diagnostic information from the
running kernel, "/proc/kcore" should be provided.  Its functionality is grouped
into _modules_, each one producing diagnostic information about a specific
kernel subsystem.

Corelens may be run in two modes: generating a report, or running specified
modules. When generating a report, corelens will run a collection of default
modules, with default arguments. Alternatively, the user may run a list of
specified modules. Each module must be specified on the command line with
*-M* _MODULE_, and any subsequent argument (up to the next *-M*) is handled by
_MODULE_.

By default, corelens produces output on stdout. However, with *-o*, output may
be stored in a directory, where each module's output is contained in a separate
file. This mode is useful when preparing a report to send to Oracle Linux
Support.

# OPTIONS

_VMCORE_
	The kernel image to run against. Specify "/proc/kcore" for the running
	kernel. This argument is required, unless using *-h* to get help, or
	*-L* to list corelens modules.

*--output-directory* _OUT_, *-o* _OUT_
	Write each module's output to a correspondingly named file within the
	_OUT_ directory. The directory _OUT_ will be created if it does not
	exist.

*Mode selection:*

	The following options are mutually exclusive.

	*-a*
		When specified, this runs the default corelens report, which should be
		sufficient for most cases. All standard modules are selected to be run
		with their default arguments. Modules which are not applicable (e.g.
		because the subsystem is not loaded or active) are skipped.

	*-A*
		When specified, this runs the detailed corelens report. This selects all
		modules, including those which are not run by *-a*. These detailed
		modules may produce larger amounts of output, or require a longer
		runtime. The standard report provided by *-a* should be preferred.

	*-M* _MODULE_ [...]
		Specify a corelens module to run, providing optional arguments to the
		module itself. All command-line arguments following this one are
		provided to the module, up to the next *-M* option.

		As a special case, when using *-h* to get help on a module's
		output, _VMCORE_ is not required.

	*-L*
		List all modules and exit. _VMCORE_ is not required.

	As a special case, when corelens is run without any of the above mode
	selection arguments, it runs the "sys" corelens module (as if the
	arguments provided were: *-M sys*).

*Debuginfo Selection:*

	The following options disable the standard behavior for searching for
	debuginfo, and manually provide it. They are not required. They are
	mutually exclusive to each other.

	*--ctf* _CTF_
		Corelens will manually load the CTF file _CTF_.

	*--debuginfo* _DEBUGINFO_, *-d* _DEBUGINFO_
		Corelens will search for DWARF debuginfo within the directory
		_DEBUGINFO_, which should contain a "vmlinux" file as well as
		".ko.debug" files for each relevant kernel module.

# DEBUGINFO

In order to produce diagnostic information, corelens requires some form of
debugging information for _VMCORE_. There are two possibilities:

*DWARF*
	DWARF information is the most detailed option, but it requires that the
	*debuginfo* package corresponding to _VMCORE_ (or the running kernel) is
	installed. When DWARF information is available, corelens can provide
	more detailed stack traces, and some modules only work when DWARF is
	available.

*CTF*
	CTF (Compact Type Format) is a lightweight type format. For Oracle UEK
	kernels (*kernel-uek*), CTF is always available.

Corelens automatically searches for debuginfo at startup. It prefers DWARF when
available, and uses CTF as a second choice. The search may be overridden by
using the options *--ctf* or *--debuginfo*.

# MODULES

Corelens' functionality is divided into modules. Modules have a name and can
accept command-line arguments. They are broken into three categories based on
when they are run:

. Standard modules run whenever *-a* is specified
. Detailed modules are run whenever *-A* is specified
. Manual modules are only run when explicitly requested

Some corelens modules will only run if a relevant kernel module is loaded.
Others require DWARF debuginfo. Some modules may only run against core dumps
(not /proc/kcore). Corelens will provide appropriate warnings or errors at
runtime if these situations are encountered.

The full list of modules can be viewed by running *corelens -L*. To view more
information about a specific module, including its command-line arguments, you
can run *corelens -M* _MODULE_ *-h*.

# EXAMPLES

Run the "sys" module against the live kernel:

```
corelens /proc/kcore -M sys
```

Run a default report against a live kernel, and store the report in a directory.
Then create an archive for later transmission to Oracle Linux Support:

```
corelens /proc/kcore -a -o ./report
tar -cvzf report.tar.gz ./report
```

List all modules:

```
corelens -L
```

Get help on the dentrycache module:

```
corelens -M dentrycache -h
```

# REPORTING BUGS

Please contact Oracle Linux Support to report any bugs for corelens.
