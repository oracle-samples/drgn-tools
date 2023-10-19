Changelog
=========

Unreleased
----------

Changes which are committed to git, but not yet released, may appear here.

0.5.1 - Tue, Sept 12, 2023
--------------------------

In this release we have several new helpers, as well as a lot of changes in
preparation for open-sourcing.

### Added

- 0.5.1 patch adds an entry point for the "corelens" script.
- Debuginfo fetching API is added. An implementation which downloads from the
  public Yum debuginfo repositories is added. The debuginfo fetching is
  configurable via `~/.config/drgn_tools.ini`.
- New testing framework, "litevm", enables testing drgn-tools without creating
  large VM images. This is suitable for use in environments like Github actions.
- New helpers
  - RDS
  - Dentry cache
  - File cache
  - Sysctl

### Changed

- The required drgn version is 0.0.24.
- Existing VM testing framework has been renamed to "heavyvm".

0.4.0 - Thur, Jun 29, 2023
--------------------------

### Added

- New md/raid helpers and corresponding corelens module.
- New RDS helper and corresponding corelens module.

### Changed

- Test VMs are now updated to OL8.8 and OL9.2.
- The minimum requirement for drgn is not 0.0.23, the latest release.

### Fixes

- Fix for the SMP CSD helpers.
- An optimization has been added to the symbol loader for modules which don't
  have debuginfoa available.

0.3.0 - Tue, May 23, 2023
-------------------------

### Added

- The `drgn_tools.corelens` script has finally become more useful and less
  preliminary. This is intended to be an automatic mechanism for running
  analysis code and printing its results to either stdout, or to a
  sosreport-like directory.
  - The command line interface is changed & much improved from the preliminary
    version released in 0.2.0, thanks to feedback in the Drgn Biweekly meeting.
  - Helpers may implement Corelens "modules", which can then be executed on the
    command line with arguments, or executed automatically in bulk using their
    default arguments.
  - The Corelens system handles ensuring that debuginfo is loaded for the
    correct kernel modules. It defaults to using DWARF debuginfo, but it
    supports the new provisional CTF API provided by the internal Drgn builds.
  - Many pre-existing helpers now have corelens modules, as well as the newly
    added helper modules.
  - During interactive debugging, you may use the special function `cl()`
    function to execute a corelens command.
- Added the Ext4 Directory Lock scan, which can find tasks blocked on a
  particular directory inode and identify the current owner of the lock. This
  scan depends on DWARF debuginfo for finding variables from the stack trace.
  There is a Corelens module too. Thanks to Junxiao for these.
- Added helpers for the SMP IPI subsystem. These can show pending SMP function
  calls and help see which CPU is waiting on which others. There is a Corelens
  module as well. Thanks Imran for these!

### Fixed

- The `drgn_tools.debuginfo` script now correctly outputs the filename `vmlinux`
  rather than `vmlinux.ko.debug`, as it did before.

0.2.0 - Tue, April 25, 2023
---------------------------

### Added

- Added `drgn_tools.debuginfo` CLI script. This can be called with a UEK release
  string to find vmlinux, extracting it if necessary. In the process, it will
  also update the access time in the `access.db` file.
- Added the `drgn_tools.taint` module that has an enumeration of the module /
  kernel taint values. These aren't included in debuginfo due since they are
  preprocessor definitions.
- Added a preliminary system called `corelens` which will be able to run scripts
  against vmcores and live systems. For now, there's no major change introduced,
  and the system is just a sketch.

### Changed

- `drgn_tools.bt.bt()` now has a `show_absent` flag -- and it is **false by
  default**. This is a breaking change, but I think a welcome one. There are
  more absent variables than non-absent in your average stack trace, and they
  take up a lot of space to show you absolutely nothing. So now, they are hidden
  by default to free up some real estate on your screen.
- `drgn_tools.bt` has now been refactored into several helper functions. Please
  see the module documentation for more information. TL;DR: if you wanted to get
  expanded stack trace frames, without printing them, you're now in luck!

### Fixed

- A relatively uncommon `FaultError` in `bt()` was fixed
- Fixed some address computation bugs for exported module symbols
- Lots of documentation and testing improvements!

0.1.0 - Tue, Mar 14, 2023
-------------------------

- Improvements to the CLI:
  - Debuginfo extraction support is now here! When the `/share/linuxrpm`
    directory exists, the `DRGN` CLI will automatically extract the vmlinux in
    the case where it is not found.
  - Module debuginfo extraction support! You can ask drgn-tools to load an
    individual module's debuginfo, and optionally extract it when necessary:
    `KernelModule.load_debuginfo(extract=True)`. You can also ask to load a list
    of module debuginfo, or all debuginfo, with
    `drgn_tools.module.load_module_debuginfo()`. Finally, you can have the
    `DRGN` CLI automatically load all module debuginfo with `DRGN -x`.
  - `dmesg(prog)` will open the kernel log in a pager for easy reading.
  - The CLI contains a few more commonly used helpers from drgn_tools
- The `drgn.helpers.linux.idr` module has been patched to include support for
  UEK4. This patch (by Imran) is already integrated in `drgn` main branch, but
  has not been released and won't see release there for a while. So it's
  included in `drgn_tools`. In order for the "patch" to apply, you need to
  import `drgn_tools` -- even if you're not using it.
- Symbol loading for modules without DWARF debuginfo was further improved: now,
  module symbols can be found using the exported symbol and GPL symbol list on
  the `struct module *`. This information is combined with module kallsyms to
  provide a decent baseline level of support even for modules without debuginfo.
  The only area where this would be less helpful is for purposely obfuscated
  modules, e.g. antivirus. It's quite helpful for giving you better backtrace
  information.
- Added NVMe helpers by Ritika.
- Added In-Flight I/O helpers by Junxiao.
- Added Workqueue helpers by Imran.
- Improvements to the CI testing:
  - Each OL and UEK version now shows up under its own collapsible sub-header in
    the CI testing output. This makes it easier to scan the output and find what
    you're interested in.
  - Fixed a flaky block test by retrying it, so test results should be more
    reliable now.

0.0.7 - Tue, Feb 14, 2023
-------------------------

- Really fixed the version string

0.0.6 - Tue, Feb 14, 2023
-------------------------

- Fixed the version string
- Fixed missing newline in cli header

0.0.5 - Tue, Feb 14, 2023
-------------------------

- Minor improvements to module symbol table lookup and backtrace printing.
- Minor improvements to CLI code to support unreleased drgn changes.
- Add `redirect_stdout()`

0.0.4 - Fri, Jan 13, 2023
-------------------------

Some major improvements to the backtrace helper:

- Use `bt(prog, cpu=5)` as a shortcut for backtracing the active task.
- Get rid of the return value unless requested.
- Lookup symbols in the module symbol table even without debuginfo.

Updated the kernel module helper and added the ability to lookup symbols.

Added a CLI wrapper which can automatically locate the vmlinux: DRGN.

0.0.3 - Mon, Jan 9, 2023
------------------------

Adds the backtrace helper.

0.0.2 - Mon, Jan 9, 2023
------------------------

This the first release for internal distribution, with more helpers.

Contains additional helpers:
- virtio
- kernel module helpers
- logging

0.0.1 - Mon, Jul 25, 2022
-------------------------

- Initial release, containing one helper and some documentation.
