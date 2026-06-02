# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Kernel RPM resolution/download/extract orchestration for testing.vm."""
import os
import shlex
import shutil
import sqlite3
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List
from urllib.error import HTTPError

from drgn_tools.util import head_file
from testing.litevm.rpm import cached_file_path
from testing.litevm.rpm import check_file_cached
from testing.litevm.rpm import DEBUGINFO_URL
from testing.litevm.rpm import download_file_cached
from testing.litevm.rpm import REPODATA
from testing.litevm.rpm import UEK_YUM
from testing.vm.config import KernelCategory
from testing.vm.config import KernelKind
from testing.vm.config import KernelVer
from testing.vm.config import VmLayout
from testing.vm.logging import VmLogger


UEKNEXT_YUM = "https://yum.oracle.com/repo/OracleLinux/OL{ol_ver}/developer/UEKnext/{arch}/"
RHCK_YUM = (
    "https://yum.oracle.com/repo/OracleLinux/OL{ol_ver}/baseos/latest/{arch}/"
)


def _cache_key(category: KernelCategory, kind: str) -> str:
    return "{}/{}".format(category.slug, kind)


def _require_cached_file(
    category: KernelCategory,
    kind: str,
    url: str,
    layout: VmLayout,
) -> Path:
    path = cached_file_path(
        url, layout.yum_cache_dir, _cache_key(category, kind)
    )
    if not path.is_file():
        raise RuntimeError(
            "Cached file is missing for {}: {} (disable --skip-rpm-fetch)".format(
                category.slug, path
            )
        )
    return path


def _yum_base(category: KernelCategory) -> str:
    fmtdict = category._asdict()
    if category.kind == KernelKind.UEKNEXT:
        fmt = UEKNEXT_YUM
    elif category.kind == KernelKind.RHCK:
        fmt = RHCK_YUM
    else:
        fmt = UEK_YUM
        fmtdict["uek_ver"] = category.uek_ver
    return fmt.format_map(fmtdict)


def _fetch_repomd(
    category: KernelCategory,
    layout: VmLayout,
    skip_fetch: bool,
    verbose: bool,
) -> Path:
    index_url = _yum_base(category) + REPODATA
    if skip_fetch:
        return _require_cached_file(category, "db", index_url, layout)
    return download_file_cached(
        index_url,
        quiet=not verbose,
        desc="Fetching index",
        cache=layout.yum_cache_dir,
        cache_key=_cache_key(category, "db"),
    )


def _fetch_primary_db(
    category: KernelCategory,
    layout: VmLayout,
    skip_fetch: bool,
    verbose: bool,
) -> Path:
    repomd = ET.fromstring(
        _fetch_repomd(category, layout, skip_fetch, verbose).read_text()
    )
    ns = "http://linux.duke.edu/metadata/repo"
    primary_db_node = repomd.findall(
        ".//{{{}}}data[@type='primary_db']/{{{}}}location".format(ns, ns)
    )[0]
    db_url = _yum_base(category) + primary_db_node.attrib["href"]
    if skip_fetch:
        db_path = _require_cached_file(category, "db", db_url, layout)
    else:
        db_path = download_file_cached(
            db_url,
            quiet=not verbose,
            cache=layout.yum_cache_dir,
            cache_key=_cache_key(category, "db"),
            desc="Fetching primary_db",
            delete_on_miss=False,
        )
    if db_path.name.endswith(".bz2"):
        db_path_dec = db_path.parent / db_path.name[: -len(".bz2")]
        if not db_path_dec.is_file():
            if verbose:
                print("Decompressing primary_db")
            subprocess.run(["bunzip2", "-k", "-q", str(db_path)], check=True)
        db_path = db_path_dec
    return db_path


def _version_sort_key(row: tuple) -> tuple:
    return tuple(map(int, row[0].split(".") + row[1].split(".")[:-1]))


def _rpm_url(base_url: str, pkgbase: str, pkgname: str) -> str:
    return base_url.replace(pkgbase, pkgname)


def _resolve_urls(
    category: KernelCategory,
    release: str,
    href: str,
    layout: VmLayout,
    skip_fetch: bool,
) -> List[str]:
    base_url = _yum_base(category) + href
    urls = []
    for pkg in category.rpms():
        if (
            pkg.startswith("kernel-devel")
            and category.kind == KernelKind.RHCK
            and category.ol_ver >= 9
        ):
            # RHCK put kernel-devel in appstream from OL9
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

    if skip_fetch:
        # In skip_fetch mode, verify the files are downloaded
        for url in urls:
            _require_cached_file(category, "rpm", url, layout)
    else:
        # Otherwise, ensure that the files are either downloaded or
        # at least present on the repo. If not present, we can fall back to an
        # older version according to palicy.
        key = _cache_key(category, "rpm")
        for url in urls:
            if not (
                check_file_cached(url, layout.yum_cache_dir, key)
                or head_file(url)
            ):
                return []
    return urls


def resolve_kernel(
    category: KernelCategory,
    paths: VmLayout,
    log: VmLogger,
    skip_fetch: bool = False,
) -> KernelVer:
    """
    Given a kernel category, determine the latest available version

    :param category: OL + UEK version to download
    :param paths: pointer to data directory
    :param log: logger for tasks
    :param skip_fetch: if set, we will avoid fetching anything from the network,
      but all the data should already be present and cached locally
    """
    db_path = _fetch_primary_db(category, paths, skip_fetch, log.verbose)
    conn = sqlite3.connect(str(db_path))
    rows = conn.execute(
        """
        SELECT version, release, location_href FROM packages
        WHERE name=? AND arch=?;
        """,
        (category.rpmbase, category.arch),
    ).fetchall()
    conn.close()

    allow_missing = bool(
        int(os.environ.get("DRGN_TOOLS_ALLOW_MISSING_LATEST", 0))
    )
    rows.sort(key=_version_sort_key, reverse=True)
    versions_tried = []
    for ver, rel, href in rows[:5]:
        release = "{}-{}.{}".format(ver, rel, category.arch)
        urls = _resolve_urls(category, release, href, paths, skip_fetch)
        if urls:
            return KernelVer(category, release, urls)
        if allow_missing:
            versions_tried.append(release)
            if log.verbose:
                print(
                    "warning: {} had missing RPMs\nTrying an older release...".format(
                        release
                    )
                )
            continue
        raise RuntimeError(
            "Required RPMs were unavailable for {} ({})".format(
                category.slug, release
            )
        )
    raise RuntimeError(
        "No release had all files available. Tried: {}".format(
            ", ".join(versions_tried)
        )
    )


def _download_kernel_rpms(
    kernel: KernelVer,
    layout: VmLayout,
    log: VmLogger,
) -> List[Path]:
    paths = []
    try:
        for i, url in enumerate(kernel.urls):
            desc = (
                "Debuginfo RPM"
                if i == len(kernel.urls) - 1
                else "RPM {}/{}".format(i + 1, len(kernel.urls) - 1)
            )
            path = download_file_cached(
                url,
                quiet=not log.verbose,
                desc=desc,
                cache=layout.yum_cache_dir,
                cache_key=_cache_key(kernel.category, "rpm"),
                delete_on_miss=(i == 0),
            )
            paths.append(path)
    except HTTPError as e:
        raise RuntimeError(
            "HTTP error {} {} encountered while fetching URL:\n{}".format(
                e.code, e.reason, e.url
            )
        )
    return paths


def _cached_kernel_rpms(kernel: KernelVer, layout: VmLayout) -> List[Path]:
    return [
        _require_cached_file(kernel.category, "rpm", url, layout)
        for url in kernel.urls
    ]


def _extract_rpms(paths: List[Path], kernel: KernelVer, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=False)
    try:
        out_dir_str = shlex.quote(str(out_dir))
        for path in paths:
            path_str = shlex.quote(str(path))
            subprocess.run(
                "rpm2cpio {} | cpio -id -D {} --quiet".format(
                    path_str, out_dir_str
                ),
                shell=True,
                check=True,
            )
        subprocess.run(
            ["depmod", "-b", str(out_dir), kernel.release],
            shell=False,
            check=True,
        )
    except BaseException:
        shutil.rmtree(str(out_dir))
        raise


def ensure_kernel(
    kernel: KernelVer,
    layout: VmLayout,
    log: VmLogger,
    skip_fetch: bool = False,
) -> Path:
    """
    Given a kernel version, ensure it's downloaded and extracted
    """
    out_dir = layout.extract_path(kernel.release)
    if out_dir.is_dir():
        log.already_done("Fetch & Extract Kernel RPMs", out_dir)
        return out_dir
    log.working("Fetch & Extract Kernel RPMs", out_dir)

    if skip_fetch:
        rpm_paths = _cached_kernel_rpms(kernel, layout)
    else:
        rpm_paths = _download_kernel_rpms(kernel, layout, log)

    building_dir = layout.extract_dir / "{}.building".format(kernel.release)
    if building_dir.exists():
        if building_dir.is_dir():
            shutil.rmtree(str(building_dir))
        else:
            building_dir.unlink()

    layout.extract_dir.mkdir(parents=True, exist_ok=True)
    try:
        _extract_rpms(rpm_paths, kernel, building_dir)
        os.rename(str(building_dir), str(out_dir))
    except BaseException:
        if building_dir.exists():
            shutil.rmtree(str(building_dir))
        raise
    log.done("Fetch & Extract Kernel RPMs", out_dir)
    return out_dir
