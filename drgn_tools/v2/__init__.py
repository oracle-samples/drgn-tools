# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Modules for drgn_tools v2.

This package contains corelens modules which are used internally and under
development, but not considered ready for customer use. The entire drgn_tools/v2
directory is deleted during the RPM build process, ensuring these modules can't
be used by customers.

ALL MODULES HERE ARE FULLY UNSUPPORTED.

Convention is to move only the ``CorelensModule`` class definition into the
``drgn_tools/v2`` directory. Supporting helper code remains in the
``drgn_tools`` package. Please understand that the ``drgn_tools`` API, while
documented to some extent, is considered unsupported and fully private. The only
public, supported interface to drgn-tools is ``corelens``.
"""
