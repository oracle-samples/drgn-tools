# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
RPM Fetching for Tests
"""
import argparse
import fnmatch
import io
import os
import shlex
import shutil
import sqlite3
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List
from typing import Optional
from typing import Union
from urllib.error import HTTPError

from drgn_tools.util import download_file
from drgn_tools.util import head_file
from testing.util import BASE_DIR


UEK_YUM = (
    "https://yum.oracle.com/repo/OracleLinux/OL{ol_ver}/UEKR{uek_ver}/{arch}/"
)
REPODATA = "repodata/repomd.xml"

DEBUGINFO_URL = "https://oss.oracle.com/ol{ol_ver}/debuginfo/{pkgbase}-debuginfo-{release}.rpm"

YUM_CACHE_DIR = BASE_DIR / "yumcache"


def download_file_cached(
    url: str,
    quiet: bool = False,
    desc: str = "Downloading",
    cache: Optional[Path] = None,
    cache_key: Optional[str] = None,
    delete_on_miss: bool = True,
) -> Path:
    """
    Download a file into the cache directory

    This function is designed to work seamlessly with the Github Actions cache,
    but would also work well with a simple cache directory with no Github
    Actions magic. The cache has a directory structure, and each kind of file
    gets put under a separate subdirectory. When downloading a file, we search
    the subdirectory, and if it already exists, there is a cache hit and we can
    skip the download. If the file does not exist, it's a cache miss and we
    download the file. In that case, the cache contents may be stale, so we can
    clear out the previous contents (this behavior can be skipped in case you're
    keeping several files in the directory).

    When used properly, the cache directory will speed up operation by skipping
    downloads. And when a newer version of the downloaded resources becomes
    available, the old resources are removed from the directory, so that the
    size is minimized.

    :param url: Url to download. The last path component is the filename
    :param quiet: Whether to print progress
    :param desc: Description for progress printing
    :param cache: Location of the cache directory
    :param cache_key: Key providing isolation within the cache. It's treated as
      a path component, so it can have slashes which introduce subdirectories.
    :param delete_on_miss: Whether to delete all files under the cache_key
      during a cache miss. Set this to False if your cache_key contains multiple
      files which will all miss in a row. Note that delete_on_miss is only
      respected when cache_key is not None.
    :returns: Path of the downloaded or cached file
    """
    if not cache:
        cache = YUM_CACHE_DIR
    if cache_key:
        cache = cache / cache_key
    cached_file = cache / url.split("/")[-1]
    cached_file.parent.mkdir(exist_ok=True, parents=True)
    if not cached_file.is_file():
        if cache_key and delete_on_miss and cached_file.parent.is_dir():
            shutil.rmtree(cached_file.parent)
        cached_file.parent.mkdir(exist_ok=True, parents=True)
        with cached_file.open("wb+") as cache_f:
            try:
                download_file(url, cache_f, quiet=quiet, desc=desc)
            except BaseException:
                # Yes, BaseException is correct. If we're interrupted for _any_
                # reason, our cached downolad is invalid and must be removed.
                cache_f.close()
                cached_file.unlink()
                raise
    return cached_file


def check_file_cached(
    url: str, cache: Optional[Path], cache_key: Optional[str]
) -> bool:
    if not cache:
        cache = YUM_CACHE_DIR
    if cache_key:
        cache = cache / cache_key
    cached_file = cache / url.split("/")[-1]
    rv = cached_file.is_file() or head_file(url)
    return rv


class TestKernel:
    ol_ver: int
    uek_ver: Union[int, str]
    arch: str
    pkgs: List[str]

    cache_dir: Path

    def __init__(
        self,
        ol_ver: int,
        uek_ver: Union[int, str],
        arch: str,
        pkgs: List[str],
        cache_dir: Optional[Path] = None,
        pkgbase: str = "kernel-uek",
        yum_fmt: Optional[str] = None,
    ) -> None:
        self.ol_ver = ol_ver
        self.uek_ver = uek_ver
        self.arch = arch
        self.pkgs = pkgs
        self.yum_fmt = yum_fmt
        self.pkgbase = pkgbase

        self._release: str = ""
        self._rpm_urls: List[str] = []
        self._dbinfo_url: str = ""

        self._rpm_paths: List[Path] = []
        self._dbinfo_path: Path
        if cache_dir:
            self.cache_dir = cache_dir
        else:
            self.cache_dir = YUM_CACHE_DIR

    def latest_release(self) -> str:
        if not self._release:
            self._getlatest()
        # getlatest will set release to a str
        return self._release  # type: ignore

    def slug(self) -> str:
        return f"ol{self.ol_ver}uek{self.uek_ver}{self.arch}"

    def _cache_key(self, kind: str) -> str:
        return f"{self.slug()}/{kind}"

    def _getlatest(self) -> None:
        # Fetch Yum index (repomd.xml) to get the database filename.
        # This is never cached, and it's a small file.
        yumbase = (self.yum_fmt or UEK_YUM).format(
            ol_ver=self.ol_ver,
            uek_ver=self.uek_ver,
            arch=self.arch,
        )
        index_url = yumbase + REPODATA
        xml = io.BytesIO()
        download_file(index_url, xml, desc="Fetching index", quiet=False)
        tree = ET.fromstring(xml.getvalue().decode("utf-8"))
        ns = "http://linux.duke.edu/metadata/repo"
        primary_db_node = tree.findall(
            f".//{{{ns}}}data[@type='primary_db']/{{{ns}}}location"
        )[0]

        # Now fetch the database and decompress it if necessary
        db_url = yumbase + primary_db_node.attrib["href"]
        db_path = download_file_cached(
            db_url,
            cache=self.cache_dir,
            cache_key=self._cache_key("db"),
            desc="Fetching primary_db",
        )
        if db_path.name.endswith(".bz2"):
            db_path_dec = db_path.parent / db_path.name[: -len(".bz2")]
            if not db_path_dec.is_file():
                print("Decompressing primary_db")
                subprocess.run(
                    ["bunzip2", "-k", "-q", str(db_path)], check=True
                )
            db_path = db_path_dec

        # Finally, search for the latest version in the DB. We always search for
        # kernel-uek since even if the package is split, that's the
        # meta-package.
        conn = sqlite3.connect(str(db_path))
        rows = conn.execute(
            """
            SELECT version, release, location_href FROM packages
            WHERE name=? AND arch=?;
            """,
            (self.pkgbase, self.arch),
        ).fetchall()
        conn.close()

        # Sqlite can't sort versions correctly, so we load them all and sort
        # them in Python using the correct key.
        def key(t):
            return tuple(map(int, t[0].split(".") + t[1].split(".")[:-1]))

        allow_missing = bool(
            int(os.environ.get("DRGN_TOOLS_ALLOW_MISSING_LATEST", 0))
        )
        rows.sort(key=key, reverse=True)
        versions_tried = []
        for ver, rel, href in rows[:2]:
            # Check whether all RPMs are either cached or available via HTTP
            rpm_urls: List[str] = []
            rpm_url = yumbase + href
            missing_urls = []
            release = f"{ver}-{rel}.{self.arch}"
            for final_pkg in self.pkgs:
                url = rpm_url.replace(self.pkgbase, final_pkg)
                if not check_file_cached(
                    url, self.cache_dir, self._cache_key("rpm")
                ):
                    missing_urls.append(url)
                rpm_urls.append(url)
            dbinfo_url = DEBUGINFO_URL.format(
                ol_ver=self.ol_ver,
                release=release,
                pkgbase=self.pkgbase,
            )
            if not check_file_cached(
                dbinfo_url, self.cache_dir, self._cache_key("rpm")
            ):
                missing_urls.append(dbinfo_url)

            # If some RPMs are available, we have two options:
            # 1. Try the next older RPM (if the environment variable is set)
            # 2. Ignore the error and let the HTTP 404 handling below report the
            # issue.
            if missing_urls and allow_missing:
                print(
                    f"warning: {release} had missing RPMs:\n"
                    + "\n".join(missing_urls)
                    + "\nTrying an older release..."
                )
                versions_tried.append(release)
                continue

            self._rpm_urls = rpm_urls
            self._dbinfo_url = dbinfo_url
            self._release = release
            return
        else:
            # This is the case where we checked both candidates, but neither had
            # all files available. Report an error.
            sys.exit(
                "error: no release had all files available. Tried: "
                + ", ".join(versions_tried)
            )

    def _get_rpms(self) -> None:
        if not self._release:
            self._getlatest()

        self._rpm_paths = []
        try:
            for i, url in enumerate(self._rpm_urls):
                path = download_file_cached(
                    url,
                    desc=f"RPM {i + 1}/{len(self._rpm_urls)}",
                    cache=self.cache_dir,
                    cache_key=self._cache_key("rpm"),
                    delete_on_miss=(i == 0),
                )
                self._rpm_paths.append(path)
            path = download_file_cached(
                self._dbinfo_url,
                desc="Debuginfo RPM",
                cache=self.cache_dir,
                cache_key=self._cache_key("rpm"),
                delete_on_miss=False,
            )
        except HTTPError as e:
            sys.exit(
                f"HTTP error {e.code} {e.reason} encountered while "
                f"fetching URL:\n{e.url}"
            )
        self._dbinfo_path = path

    def get_rpms(self) -> List[Path]:
        if not hasattr(self, "_dbinfo_path"):
            self._get_rpms()
        return self._rpm_paths + [self._dbinfo_path]

    def delete_cache(self) -> None:
        """Removes all RPMs and the RPM cache."""
        tree = self.cache_dir / self.slug()
        shutil.rmtree(tree)

    def get_oot_modules(self) -> List[Path]:
        key = f"ol{self.ol_ver}uek{self.uek_ver}{self.arch}"
        path = Path(__file__).parent / "mod" / key
        if not path.is_dir():
            return []
        return list(path.iterdir())


TEST_KERNELS = [
    # UEK-next is a snapshot of the latest upstream kernel, with UEK
    # configurations and any customizations. It's not officially supported, but
    # it's an excellent test bed to ensure we are ready to support the latest
    # upstream features.
    TestKernel(
        9,
        "next",
        "x86_64",
        [
            "kernel-ueknext-core",
            "kernel-ueknext-modules",
            "kernel-ueknext-modules-core",
        ],
        yum_fmt=(
            "https://yum.oracle.com/repo/OracleLinux/OL{ol_ver}/"
            "developer/UEK{uek_ver}/{arch}/"
        ),
        pkgbase="kernel-ueknext",
    ),
    # UEK8 further distributes modules, so we need to add -modules-core.
    TestKernel(
        9,
        8,
        "x86_64",
        ["kernel-uek-core", "kernel-uek-modules", "kernel-uek-modules-core"],
    ),
    # UEK7 switches from a single "kernel-uek" to "-core" and "-modules".
    # The "kernel-uek" package still exists as a placeholder.
    TestKernel(9, 7, "x86_64", ["kernel-uek-core", "kernel-uek-modules"]),
    TestKernel(8, 6, "x86_64", ["kernel-uek"]),
    # UEK5 is based on 4.14. 9p is available and supported here, but
    # unfortunately the UEK kernel configuration does not enable CONFIG_9P_FS.
    # Thankfully, this can be resolved by simply building the module
    # out-of-tree.
    TestKernel(7, 5, "x86_64", ["kernel-uek"]),
    # UEK4 is based on 4.1. Unfortunately, 9p is not supported as an overlay
    # lower filesystem here. The changes required in order to make overlayfs
    # support 9p are too invasive; we can't simply replace the overlay module
    # since a backport would require changing core VFS routines. Therefore, UEK4
    # cannot be tested via this lightweight mechanism.
    #
    # TestKernel(7, 4, "x86_64", ["kernel-uek"]),
]


def extract_rpms(paths: List[Path], out_dir: Path, kernel: TestKernel) -> None:
    """
    Extract the list of RPMs to an output directory.

    The output directory must not exist. On any failure, the output directory is
    deleted. On success, all RPMs are guaranteed to be extracted into the
    new directory. This means that you can rely on "is_dir()" checks to verify
    that the RPMs are already extracted, and avoid redoing the costly
    extraction.
    """
    release = kernel.latest_release()
    out_dir.mkdir(parents=True, exist_ok=False)
    try:
        out_dir_str = shlex.quote(str(out_dir))
        for path in paths:
            path_str = shlex.quote(str(path))
            subprocess.run(
                f"rpm2cpio {path_str} | cpio -id -D {out_dir_str} --quiet",
                shell=True,
                check=True,
            )
        mod_dir = out_dir / "lib/modules" / release
        for mod in kernel.get_oot_modules():
            shutil.copy(mod, mod_dir / mod.name)
        subprocess.run(
            ["depmod", "-b", out_dir_str, release],
            shell=False,
            check=True,
        )
    except BaseException:
        shutil.rmtree(out_dir)
        raise


def main():
    parser = argparse.ArgumentParser(description="Lite VM RPM Download")
    parser.add_argument(
        "--yum-cache-dir",
        type=Path,
        default=BASE_DIR / "yumcache",
        help="Directory to store Yum Repo and RPM data",
    )
    parser.add_argument(
        "--kernel",
        help="Match against the given kernel (eg *uek6*)",
    )
    args = parser.parse_args()
    for kernel in TEST_KERNELS:
        kernel.cache_dir = args.yum_cache_dir
        if args.kernel and not fnmatch.fnmatch(kernel.slug(), args.kernel):
            continue
        release = kernel.latest_release()
        print(
            f"Latest for OL{kernel.ol_ver}, UEK{kernel.uek_ver},"
            f" {kernel.arch}: {release}"
        )
        kernel.get_rpms()


if __name__ == "__main__":
    main()
