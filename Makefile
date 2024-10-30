# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/

VERSION=$(shell grep 'RELEASE_VERSION =' setup.py | sed s/\"//g | awk '{print($$3)}')

PYTHON ?= python3

# This allows you to add custom configuration:
# TARGET: set the target for "make rsync"
# It also allows creating custom targets, e.g. for development
-include config.mk

.PHONY: litevm-test
litevm-test:
	$(PYTHON) -m testing.litevm.vm


.PHONY: vmcore-test
vmcore-test:
	$(PYTHON) -m testing.vmcore test


.PHONY: test
test: litevm-test vmcore-test

.PHONY: docs
docs:
	@$(PYTHON) -m tox -e docs

drgn_tools/_version.py:
	$(PYTHON) setup.py -V

.PHONY: rsync
rsync: drgn_tools/_version.py
	@if [ -z "$(TARGET)" ]; then echo "error: TARGET unspecified. Either set it in config.mk, or use\nmake TARGET=hostname rsync"; exit 1; fi
	rsync -avz --exclude "__pycache__" --exclude ".git" --exclude ".mypy_cache" ./drgn_tools $(TARGET):drgn_tools/
