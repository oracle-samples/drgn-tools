# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html
# -- Path setup --------------------------------------------------------------
import os
import re

# -- Project information -----------------------------------------------------

project = "drgn-tools"
copyright = "2023, Oracle and/or its affiliates"
author = "Oracle and/or its affiliates"

# The full version, including alpha/beta/rc tags
with open(os.path.join(os.path.dirname(__file__), "..", "setup.py")) as f:
    match = re.search(r"VERSION = \"(.+)\"", f.read())
    assert match, "VERSION variable not found in setup.py"
    release = "v" + match.group(1)


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx.ext.autodoc",
    "sphinx_autodoc_typehints",
    "sphinx_reference_rename",
    "sphinx.ext.intersphinx",
    "myst_parser",
]
autodoc_typehints = "description"

nitpicky = True

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

nitpick_ignore = [('py:class', 'drgn_tools.itertools.T')]

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "alabaster"

# Free, no attribution required, quick logo.
# https://logodust.com
html_logo = "drgn-tools.png"
html_favicon = "drgn-tools.png"

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = [""]

# -- Options for Intersphinx linking (linking to external docs)
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "pandas": ("https://pandas.pydata.org/pandas-docs/stable", None),
    "matplotlib": ("https://matplotlib.org", None),
    "drgn": ("https://drgn.readthedocs.io/en/latest/", None),
}

sphinx_reference_rename_mapping = {
    "_drgn.IntegerLike": "drgn.IntegerLike",
    "_drgn.Object": "drgn.Object",
    "_drgn.Program": "drgn.Program",
    "_drgn.Thread": "drgn.Thread",
    "_drgn.Type": "drgn.Type",
    "_drgn.StackFrame": "drgn.StackFrame",
    "_drgn.StackTrace": "drgn.StackTrace",
}

# Allow markdown files
source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}


# Logic below skips the subclasses of CorelensModule. They're not interesting
# documentation for developers.
def should_skip_class(app, what, name, obj, skip, options):
    if what == "module":
        from drgn_tools.corelens import CorelensModule

        try:
            if issubclass(obj, CorelensModule) and obj is not CorelensModule:
                return True
        except Exception:
            pass

    return None


def setup(app):
    app.connect("autodoc-skip-member", should_skip_class)
