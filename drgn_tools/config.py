# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Configuration support

Ideally drgn-tools shouldn't require much in the way of configuration, but some
things like debuginfo fetching are better if they can be configured.
"""
import configparser
from functools import lru_cache
from pathlib import Path

__all__ = ("get_config",)


CONFIG_PATHS = [
    Path("/etc/drgn_tools.ini"),
    Path.home() / ".config/drgn_tools.ini",
]


@lru_cache(maxsize=1)
def get_config() -> configparser.ConfigParser:
    """
    Return drgn-tools configuration information
    """
    config = configparser.ConfigParser()
    config.read(CONFIG_PATHS)
    return config
