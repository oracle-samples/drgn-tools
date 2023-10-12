# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from typing import Any

from drgn_tools.debuginfo import KernelVersion


def parse_check_fields(name: str, **kwargs: Any):
    ver = KernelVersion.parse(name)
    defaults = {
        "ol_update": None,
        "arch": "x86_64",
        "extraversion1": "",
        "extraversion2": "",
        "is_uek": True,
    }
    defaults.update(kwargs)
    for field_name, value in defaults.items():
        assert getattr(ver, field_name) == value


def test_uek_versions():
    # UEK7, OL9
    parse_check_fields(
        "5.15.0-101.103.2.1.el9uek.x86_64",
        release="101.103.2.1",
        ol_version=9,
    )

    # UEK7, OL8
    parse_check_fields(
        "5.15.0-101.103.2.1.el8uek.x86_64",
        version="5.15.0",
        release="101.103.2.1",
        ol_version=8,
    )

    # UEK6, OL8
    parse_check_fields(
        "5.4.17-2136.323.7.el8uek.x86_64",
        version="5.4.17",
        release="2136.323.7",
        ol_version=8,
    )

    # UEK6, OL7
    parse_check_fields(
        "5.4.17-2136.323.7.el7uek.x86_64",
        version="5.4.17",
        release="2136.323.7",
        ol_version=7,
    )

    # An older UEK6
    parse_check_fields(
        "5.4.17-2006.5.el8uek.x86_64",
        version="5.4.17",
        release="2006.5",
        ol_version=8,
    )

    # UEK5, OL7
    parse_check_fields(
        "4.14.35-2047.528.2.1.el7uek.x86_64",
        version="4.14.35",
        release="2047.528.2.1",
        ol_version=7,
    )

    # UEK4, OL7
    parse_check_fields(
        "4.1.12-124.48.6.el7uek.x86_64",
        version="4.1.12",
        release="124.48.6",
        ol_version=7,
    )


def test_rhck():
    # OL9
    parse_check_fields(
        "5.14.0-284.25.1.0.1.el9_2.x86_64",
        version="5.14.0",
        release="284.25.1.0.1",
        ol_version=9,
        ol_update=2,
        is_uek=False,
    )

    # OL8 without update?
    parse_check_fields(
        "4.18.0-193.el8.x86_64",
        version="4.18.0",
        release="193",
        ol_version=8,
        is_uek=False,
    )

    # OL8 with update
    parse_check_fields(
        "4.18.0-193.1.2.el8_2.x86_64",
        version="4.18.0",
        release="193.1.2",
        ol_version=8,
        ol_update=2,
        is_uek=False,
    )

    # OL7 (never has update)
    parse_check_fields(
        "3.10.0-1160.99.1.0.1.el7.x86_64",
        version="3.10.0",
        release="1160.99.1.0.1",
        ol_version=7,
        is_uek=False,
    )


def test_uek_aarch64():
    # OL8/9 + UEK7 is the main target
    parse_check_fields(
        "5.15.0-104.119.4.2.el9uek.aarch64",
        version="5.15.0",
        release="104.119.4.2",
        ol_version=9,
        arch="aarch64",
    )
    parse_check_fields(
        "5.15.0-106.125.1.el8uek.aarch64",
        version="5.15.0",
        release="106.125.1",
        ol_version=8,
        arch="aarch64",
    )
    # no rhck for aarch64
