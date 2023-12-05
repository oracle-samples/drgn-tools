Contributing: Code Quality Guidelines
=====================================

Now that you can make changes to drgn-tools and test them out on vmcores, this
guide will help you get those changes merged.

Development Process
-------------------

Rather than using an email and patch-based workflow, we use Github and pull
requests to help maintain drgn-tools. This gives several advantages: Github
allows us to do Continuous Integration to test your changes. The Github code
review system can allow for more focused discussion, and it tracks code review
issues, requiring you to resolve each discussion before moving forward.

The basic workflow is simple:

1. Fork the Github repository and clone your fork.
2. On your development machine, create a branch based on the latest ``main``
   branch. Make whatever changes you need, and commit your changes. Please try
   to separate your changes into commits with meaningful messages, and use ``git
   commit -s`` to sign-off on your commits.
3. Push your branch back to your fork.
4. Create a pull request in the Github UI.
5. Respond to review comments! In order to submit a new revision of your branch,
   you can simply push new commits. You can also rebase your branch and push it
   with ``git push origin HEAD --force-with-lease``. Ideally, you should try
   amend and rebase changes as necessary, rather than adding lots of follow-up
   commits fixing small issues.
6. Once your changes are merged, they will be included in the next drgn-tools
   release, which may be in a few weeks. If you have any timing requirements, we
   can create releases sooner, just ask.

Code Quality: Static Checks
---------------------------

When you make a commit, some "pre-commit hooks" will run, doing various checks
(and possibly changes) on your code. The commit will not succeed until you have
made sure all the static checks and formatters are successful. This describes
all the checks and how to deal with them.

Format
^^^^^^

For the most part, you shouldn't need to think too hard about code format, since
the pre-commit hook will use the "Black" source code formatter to automatically
format your code. But here are a few high level, common Python style guidelines:

- Use 4 spaces for indentation
- Use 2 newlines to separate functions, 1 newline to separate class methods
- Name functions using ``snake_case`` and classes using ``PascalCase``
- Try to keep it to 80 characters for a line

Some other guidelines are enforced by our pre-commit hooks:

- No trailing whitespace in files
- Python imports should be ordered as follows: (`see docs for details`__)

  - Split into three groups: standard library, third-party modules (i.e. drgn),
    and then internal imports (e.g. drgn_tools).
  - ``import`` imports before ``from`` imports
  - One import per line, no duplicates
  - Ordered alphabetically

__ https://github.com/asottile/reorder_python_imports#what-does-it-do

Static Checking
^^^^^^^^^^^^^^^

To avoid some simple errors, the Flake8 static checker runs as a pre-commit hook
as well. This will raise errors and warnings about common code smells---for
example, unused variables. This checker will not automatically fix these issues,
but they should be self-explanatory. If you run into issues, share the error
message and code contents on via Github issues.

Type Annotations (mypy hook)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Recent Python 3 versions allow you to "annotate" the expected argument and
return types of functions. It is done like so:

.. code-block:: python

    def happy_birthday_message(name: str, age: int) -> str:
        ones = age % 10
        tens = age % 100 - ones
        if ones == 1 and tens != 10:
            return f"happy {age}st birthday, {name}!"
        elif ones == 2 and tens != 10:
            return f"happy {age}nd birthday, {name}!"
        elif ones == 3 and tens != 10:
            return f"happy {age}rd birthday, {name}!"
        return f"happy {age}th birthday, {name}!"

For function arguments, the type is separated from the name by a colon, and for
return types, the type comes after the signature separated by an arrow (``->``).
Functions with no return value should specify a return type of ``None``.

All functions should have these annotations, and the ``mypy`` hook is used to
enforce this requirement. The result of having these annotations is that the
``mypy`` hook can also perform static checks and warnings, such as telling you
when you do something that would cause a ``TypeError``, or when you access a
field that an object doesn't have.

These can be trickier to resolve, if you encounter mypy errors, feel free to
immediately reach out via Github issues.

Other Requirements and Expectations
-----------------------------------

Documentation
^^^^^^^^^^^^^

Every general purpose helper requires a Python docstring, which documents its
purpose, parameters, and return value. No exceptions! Every function's
documentation will get included in this help site, allowing users to quickly
find useful helpers.

Use ``make docs`` to generate the documentation, and open it up to see whether
your newly added functions are included in the documentation. You may need to
modify ``doc/api.rst`` to get it to show up. Feel free to reach out in via
Github issues if this is causing problems.

Kernel Compatibility
^^^^^^^^^^^^^^^^^^^^

General purpose helpers should be compatible with all supported UEK versions. If
they are not, this MUST be documented in the docstring. The CI system runs tests
on each supported UEK version. You should include tests (described in the next
article) that will exercise your helper's code so that we can easily verify the
compatibility on all UEKs.

Python Compatibility
^^^^^^^^^^^^^^^^^^^^

We expect that we will be shipping drgn-tools via RPM to customers in the
future. As a result, we need to maintain compatibility with the minimum
available Python version, Python 3.6.

Further, this means that we will not accept any Python code that depends on a
Python library other than ``drgn``. Adding third-party dependencies makes things
much more difficult.

To assist in this, there is a pre-commit hook called "vermin" (like version
minimum) which checks all code to verify it uses features compatible all the way
back to Python 3.6.
