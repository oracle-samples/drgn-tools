# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/

# Note: manual pages are written in the scd format, but rather than depend on
# scdoc for the RPM build, we simply include the resulting roff files in git.

all: corelens.1

%: %.scd
	scdoc < $< > $@
