# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/

VERSION=$(shell grep 'RELEASE_VERSION =' setup.py | sed s/\"//g | awk '{print($$3)}')

PYTHON ?= python3

# This allows you to add custom configuration:
# TARGET: set the target for "make rsync"
# It also allows creating custom targets, e.g. for development
-include config.mk
# The TARGET variable could be either a hostname or a hostname:path. Previously
# the makefile expected just a hostname, and it always placed the resulting
# directory at $TARGET:drgn_tools/. But it's nice to have flexibility to change
# the target directory, so we only add that default path if there's not already
# a path specified.
ifneq (,$(TARGET))
ifeq (,$(findstring :,$(TARGET)))
override TARGET := $(TARGET):drgn_tools/
else
endif
endif

.PHONY: litevm-test
litevm-test:
	tox --notest
	-tox -e runner -- python -m testing.litevm.vm


.PHONY: vmcore-test
vmcore-test:
	-tox -e runner -- python -m testing.vmcore test


test: litevm-test vmcore-test

.PHONY: docs
docs:
	@$(PYTHON) -m tox -e docs

drgn_tools/_version.py:
	python setup.py -V

.PHONY: rsync
rsync: drgn_tools/_version.py
	@if [ -z "$(TARGET)" ]; then echo "error: TARGET unspecified. Either set it in config.mk, or use\nmake TARGET=hostname rsync"; exit 1; fi
	rsync -avz --exclude "__pycache__" --exclude ".git" --exclude ".mypy_cache" ./drgn_tools $(TARGET)
