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
	tox --notest
	-tox -e runner -- python -m testing.litevm.vm


.PHONY: vmcore-test
vmcore-test:
	-tox -e runner -- python -m testing.vmcore test
	@cp '.tox/runner/log/2-commands[0].log' test-vmcore.log
	@echo 'View the test log files: "less -R test-vmcore.log"'


test: litevm-test vmcore-test

.PHONY: docs
docs:
	@$(PYTHON) -m tox -e docs

drgn_tools/_version.py:
	python setup.py -V

.PHONY: rsync
rsync: drgn_tools/_version.py
	@if [ -z "$(TARGET)" ]; then echo "error: TARGET unspecified. Either set it in config.mk, or use\nmake TARGET=hostname rsync"; exit 1; fi
	rsync -avz --exclude "__pycache__" --exclude ".git" --exclude ".mypy_cache" ./drgn_tools $(TARGET):drgn_tools/
