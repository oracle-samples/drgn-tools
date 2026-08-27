# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Kernel RPM resolution/download/extract orchestration for testing.vm."""
import os
import shutil
import sqlite3
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.error import HTTPError
from urllib.error import URLError

from drgn_tools.util import download_file
from drgn_tools.util import head_file
from testing.config import DEBUGINFO_URL
from testing.config import KernelCategory
from testing.config import KernelKind
from testing.config import KernelVer
from testing.config import OLVersion
from testing.config import TestDirectories
from testing.config import YUM_STALE_HOURS
from testing.util import builddir
from testing.util import rmtree_siblings
from testing.util import rmtree_siblings_matching
from testing.vm.logging import VmLogger


REPODATA = "repodata/repomd.xml"


def dest_path(dest: Path, url: str) -> Path:
    return dest / url.split("/")[-1]


def download_to_file(
    url: str,
    dest: Path,
    quiet: bool = False,
    desc: str = "Downloading",
) -> Path:
    dest.parent.mkdir(exist_ok=True, parents=True)
    with dest.open("wb") as f:
        try:
            download_file(url, f, quiet=quiet, desc=desc)
        except BaseException:
            f.close()
            dest.unlink()
            raise
    return dest


def _fetch_repomd(
    category: KernelCategory,
    dest: Path,
    skip_fetch: bool,
    log: VmLogger,
) -> Path:
    index_url = category.yum_repo() + REPODATA
    path = dest_path(dest, index_url)

    # When skip_fetch is enabled: accept any repomd, no matter the staleness,
    # and fail hard when the repomd is missing.
    if skip_fetch:
        if path.exists():
            return path
        else:
            raise RuntimeError(
                "Cached file is missing for {}: {} (disable --skip-rpm-fetch)".format(
                    category.name, path
                )
            )
    # For normal mode, invalidate the repomd file after YUM_STALE_HOURS
    if path.exists():
        statbuf = path.stat()
        if statbuf.st_mtime < time.time() - YUM_STALE_HOURS * 3600:
            path.unlink()

    if path.exists():
        # Return the path if it exists and was not stale
        return path
    else:
        # Otherwise, download it
        log.working("Fetching yum index", path.parent)
        return download_to_file(
            index_url,
            path,
            quiet=not log.verbose,
            desc="Fetching index",
        )


def _fetch_primary_db(
    category: KernelCategory,
    layout: TestDirectories,
    skip_fetch: bool,
    log: VmLogger,
) -> Path:
    dest = layout.yum_cache_dir(category)
    repomd = ET.fromstring(
        _fetch_repomd(category, dest, skip_fetch, log).read_text()
    )
    ns = "http://linux.duke.edu/metadata/repo"
    primary_db_node = repomd.findall(
        ".//{{{}}}data[@type='primary_db']/{{{}}}location".format(ns, ns)
    )[0]
    db_url = category.yum_repo() + primary_db_node.attrib["href"]
    download_path = dest_path(dest, db_url)

    if download_path.name.endswith(".sqlite"):
        final_path = download_path
    elif download_path.name.endswith(".sqlite.bz2"):
        final_path = download_path.parent / download_path.name[: -len(".bz2")]
    else:
        raise RuntimeError(f"Unrecognized RPM DB extension: {db_url}")

    # If already downloaded (and extracted), return it directly
    if final_path.exists():
        log.already_done("Fetching yum index", final_path.parent)
        return final_path

    # We may need to download
    if not download_path.exists():
        if skip_fetch:
            raise RuntimeError(
                "Cached file is missing for {}: {} (disable --skip-rpm-fetch)".format(
                    category.name, download_path
                )
            )
        else:
            download_to_file(
                db_url,
                download_path,
                quiet=not log.verbose,
                desc="Fetching primary_db",
            )

    # We may need to extract
    if download_path.name.endswith(".sqlite"):
        # No decompression necessary!
        pass
    elif download_path.name.endswith(".sqlite.bz2"):
        # deletes the compressed version on success
        subprocess.run(["bunzip2", "-q", str(download_path)], check=True)
    else:
        assert False

    # Delete any older rpmdb
    rmtree_siblings_matching(final_path, r".*\.sqlite.*")
    assert final_path.exists()
    log.done("Fetching yum index", final_path.parent)
    return final_path


def _rpm_url(base_url: str, pkgbase: str, pkgname: str) -> str:
    return base_url.replace(pkgbase, pkgname)


def _resolve_urls(
    category: KernelCategory,
    release: str,
    href: str,
) -> KernelVer:
    base_url = category.yum_repo() + href
    urls = []
    for pkg in category.rpms():
        if (
            pkg.startswith("kernel-devel")
            and category.kind == KernelKind.RHCK
            and category.ol_ver.value >= OLVersion.OL9.value
        ):
            # RHCK put kernel-devel in appstream starting with OL9
            urls.append(
                _rpm_url(
                    base_url.replace("baseos/latest", "appstream"),
                    category.rpmbase,
                    pkg,
                )
            )
        else:
            urls.append(_rpm_url(base_url, category.rpmbase, pkg))
    dbinfo_url = DEBUGINFO_URL.format(
        ol_ver=category.ol_ver,
        release=release,
        pkgbase=category.rpmbase,
    )
    urls.append(dbinfo_url)
    return KernelVer(category, release, urls)


def _kernel_version_present(ver: KernelVer, layout: TestDirectories) -> bool:
    extract_path = layout.extract_path(ver)
    libmod = extract_path / f"lib/modules/{ver.release}"
    debugmod = extract_path / f"usr/lib/debug/lib/modules/{ver.release}"
    mod_dep = extract_path / f"lib/modules/{ver.release}/modules.dep"
    return (
        extract_path.is_dir()
        and libmod.is_dir()
        and debugmod.is_dir()
        and mod_dep.is_file()
    )


def _all_rpms_available(
    ver: KernelVer, layout: TestDirectories, log: VmLogger, skip_fetch: bool
) -> bool:
    try:
        rpm_path = layout.rpm_path(ver)
        for url in ver.urls:
            dest = dest_path(rpm_path, url)
            if dest.exists():
                continue
            if not skip_fetch and head_file(url):
                continue
            log.message(f"Missing RPM: {dest.name} {url}")
            return False
        return True
    except URLError:
        raise RuntimeError(
            f"Error while verifying URLs for release: "
            f"{ver.category.name} {ver.release}"
        )


def _version_sort_key(row: tuple) -> tuple:
    return tuple(map(int, row[0].split(".") + row[1].split(".")[:-1]))


def _extract_rpm(rpm_path: Path, dest: Path) -> None:
    with subprocess.Popen(
        ["rpm2cpio", str(rpm_path)], shell=False, stdout=subprocess.PIPE
    ) as proc:
        subprocess.run(
            ["cpio", "-id", "-D", str(dest), "--quiet"],
            stdin=proc.stdout,
            shell=False,
            check=True,
        )
        proc.stdout.close()  # type: ignore[union-attr]  # stdout is piped
        if proc.wait() != 0:
            raise subprocess.CalledProcessError(proc.returncode, proc.args)


def _download_extract_rpms(
    kernel: KernelVer,
    layout: TestDirectories,
    skip_fetch: bool,
    log: VmLogger,
) -> KernelVer:
    # The per-kernel path contains the temporary rpm directory and the
    # extraction dir. EG:
    # testdata/vm/ol10-uek8-x86_64/kernel/$release/
    #  -> rpms/$foo.rpm
    #  -> root/...
    kernel_path = layout.kernel_path(kernel)
    rpm_dir = layout.rpm_path(kernel)
    paths = []
    log.working("Download & extract kernel", kernel_path)
    try:
        for i, url in enumerate(kernel.urls):
            dest = dest_path(rpm_dir, url)
            if dest.exists():
                paths.append(dest)
                continue
            # _all_rpms_available() should prevent this, but check it anyway
            assert not skip_fetch
            desc = (
                "Debuginfo RPM"
                if i == len(kernel.urls) - 1
                else "RPM {}/{}".format(i + 1, len(kernel.urls) - 1)
            )
            path = download_to_file(
                url,
                dest,
                quiet=not log.verbose,
                desc=desc,
            )
            paths.append(path)
    except HTTPError as e:
        raise RuntimeError(
            "HTTP error {} {} encountered while fetching URL:\n{}".format(
                e.code, e.reason, e.url
            )
        )
    except URLError as e:
        raise RuntimeError(
            "Error ({}) while fetching URL:\n{}".format(e.reason, url)
        )

    final_out_dir = layout.extract_path(kernel)
    if final_out_dir.exists():
        shutil.rmtree(final_out_dir)

    out_dir = builddir(final_out_dir)
    try:
        for path in paths:
            _extract_rpm(path, out_dir)
        subprocess.run(
            ["depmod", "-b", str(out_dir), kernel.release],
            shell=False,
            check=True,
        )
    except BaseException:
        # Cleanup all extraction data (but leave the RPMs in case of a later
        # try) on any error.
        shutil.rmtree(str(out_dir))
        raise
    os.rename(out_dir, final_out_dir)

    # On successful extraction, we do not need to keep the RPMs we downloaded.
    shutil.rmtree(rpm_dir)
    # Similarly, we can now clear out any prior kernels we had downloaded and
    # extracted.
    rmtree_siblings(kernel_path)
    log.done("Download & extract kernel", kernel_path)
    return kernel


def ensure_kernel(
    category: KernelCategory,
    paths: TestDirectories,
    log: VmLogger,
    skip_fetch: bool = False,
) -> KernelVer:
    """
    Given a kernel category, ensure the latest RPMs are downloaded & extracted
    in the testdata directory.

    :param category: OL + UEK version to download
    :param paths: pointer to data directory
    :param log: logger for tasks
    :param skip_fetch: if set, we will avoid fetching anything from the network,
      but all the data should already be present and cached locally
    """
    db_path = _fetch_primary_db(category, paths, skip_fetch, log)
    conn = sqlite3.connect(str(db_path))
    rows = conn.execute(
        """
        SELECT version, release, location_href FROM packages
        WHERE name=? AND arch=?;
        """,
        (category.rpmbase, category.arch.value),
    ).fetchall()
    conn.close()

    allow_missing = bool(
        int(os.environ.get("DRGN_TOOLS_ALLOW_MISSING_LATEST", 1))
    )
    rows.sort(key=_version_sort_key, reverse=True)
    versions_tried = []
    for ver, rel, href in rows[:5]:
        release = "{}-{}.{}".format(ver, rel, category.arch)
        kver = _resolve_urls(category, release, href)

        # Short circuit for a common case: the kernel RPMs were already
        # downloaded and extracted to their expected directory.
        if _kernel_version_present(kver, paths):
            log.already_done(
                "Download & extract kernel", paths.kernel_path(kver)
            )
            return kver

        # We do not cache RPMs, so if it is not extracted, there's nothing to do
        # in skip_fetch mode. For normal mode, check the latest version.
        if _all_rpms_available(kver, paths, log, skip_fetch):
            return _download_extract_rpms(kver, paths, skip_fetch, log)
        if allow_missing:
            versions_tried.append(release)
            if log.verbose:
                print(
                    "warning: {} had missing RPMs\nTrying an older release...".format(
                        release
                    )
                )
        else:
            raise RuntimeError(
                "Required RPMs were unavailable for {} ({})".format(
                    category.name, release
                )
            )
    raise RuntimeError(
        "No release had all files available. Tried: {}".format(
            ", ".join(versions_tried)
        )
    )
