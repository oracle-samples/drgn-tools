# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional


def print_table(fields: List[List[Any]]) -> None:
    """
    Print a given nested list as table, given that the first list is the column headers.

    :param fields: A nested list with the first list being the column headers and each subsequent list containing the rows.
    :param outfile: A file to write the output to.
    :param report: Open the file in append mode. Used to generate a report of all the functions in the rds module.
    :returns: None
    """

    col_widths = []
    for col in range(len(fields[0])):
        col_widths.append(max(len(str(row[col])) for row in fields))

    for entry in fields:
        print(
            "".join(
                str(val).ljust(col_width + 2)
                for (val, col_width) in zip(entry, col_widths)
            ).rstrip(),
        )


class Table:
    """
    Create an aligned, formatted table

    This helper makes it simple to create a text table which is aligned to your
    requirements, and whose values are formatted with whatever string formatter
    you'd like. The table will be written to stdout by default, but can be
    written to a custom output file if you prefer.

    To create the table, you need to specify all the columns. Each column is
    specified by a string which contains the column name, and optionally a colon
    (":") followed by a format string. You can prefix the format string with a
    "<" or ">" to control the justification of the column (it is stripped from
    the format string). By default, columns are left justified and formatted
    using ``format(value, '')`` which is typically the same as ``str()``. Here
    are some example column specifiers:

    1. "TIME:>.3f" - a column named "TIME", right justified
    2. "NAME" - a column named "NAME", left justified, formatted by str()
    3. "PTR:016x" - a 16-digit hexadecimal value, 0-filled

    Please note that this function will store all rows until ``write()`` is
    called. This way, it can determine the expected column widths for all rows,
    and align them accordingly. If you'd like your table rows to be printed as
    they are created (e.g. if producing the output takes a long time, and you'd
    like the user to see output as it becomes available), then you could use
    :class:`FixedTable`.

    :param header: a list of column specifiers, see above for details
    """

    def __init__(self, header: List[str]):
        # Name of each header
        self.header = []
        # Function (str, int) -> str to justify each column entry
        self.justifier = []
        # Format string for column
        self.formats = []
        for h in header:
            just = str.ljust
            if ":" in h:
                name, fmt = h.rsplit(":", 1)
            else:
                name, fmt = h, ""
            if len(fmt) > 0 and fmt[0] in ("<", ">"):
                if fmt[0] == ">":
                    just = str.rjust
                fmt = fmt[1:]
            self.header.append(name)
            self.justifier.append(just)
            self.formats.append(fmt)
        self.widths = [len(h) for h in header]
        self.rows: List[List[str]] = []

    def _build_row(
        self, fields: Iterable[Any], update_widths: bool = True
    ) -> List[str]:
        row = []
        for i, data in enumerate(fields):
            if i < len(self.header):
                string = format(data, self.formats[i])
            else:
                string = str(data)
            row.append(string)
            if update_widths and len(string) > self.widths[i]:
                self.widths[i] = len(string)
            self.widths[i] = max(self.widths[i], len(string))
        return row

    def add_row(self, fields: Iterable[Any]) -> None:
        """Add a row to the table (values expressed as a list)"""
        self.rows.append(self._build_row(fields))

    def row(self, *fields: Any) -> None:
        """Add a row to the table (values expressed as positional args)"""
        self.add_row(fields)

    def _row_str(self, row: List[str]) -> str:
        return "  ".join(
            j(s, w) for j, s, w in zip(self.justifier, row, self.widths)
        ).rstrip()

    def write(self) -> None:
        """Print the table to the output file"""
        print(self._row_str(self.header))
        for row in self.rows:
            print(self._row_str(row))


class FixedTable(Table):
    """
    Created an aligned, formatted table with fixed column widths

    This is a variant of the :class:`Table` class, and it is designed to be
    nearly a drop-in replacement. Unlike :class:`Table`, the column widths are
    "fixed"; that is they are set up during initialization. This means that each
    row can be printed immediately, which is great for letting users know that
    progress is being made. The trade-off is that if any row contains a column
    value which is too wide, the row will become unaligned. This is makes output
    less visually appealing, but frequently it can be avoided by designing the
    table carefully.

    The column widths can be specified in one of two ways. First, you may
    specify a list of widths to this constructor. In that case, the table header
    is immediately printed, and the given widths are used exactly as provided.
    Alternatively, you can omit the ``widths`` argument. When the first row is
    printed, column widths are calculated using the width of each value in the
    row (and also the header width) to ensure everything fits. This is an
    especially useful behavior if your table data is already fixed-width anyway:
    you don't need to hand-calculate widths and risk them going out of date.

    The other behaviors of this class are identical to :class:`Table`.  Please
    note that even though this table tends to print rows immediately, it is
    still good practice to use call ``write()`` once finished adding rows. This
    makes it trivial to swap out the implementation for :class:`Table` if
    desired.

    :param header: column specifiers for the table
    :param widths: optional list of column widths
    :param kwargs: remainder of arguments are passed to :class:`Table`
    """

    def __init__(
        self, header: List[str], widths: Optional[List[int]] = None, **kwargs
    ):
        super().__init__(header, **kwargs)
        self.print_immediately = False
        if widths:
            self.widths = widths
            self.print_immediately = True
            print(self._row_str(self.header))

    def add_row(self, fields: Iterable[Any]) -> None:
        """Add a row to the table (it is immediately printed)"""
        # Use the first row to determine widths if they weren't provided at the
        # constructor. Once that is done, print the header, and from then on, we
        # won't update the field widths as we go.
        if not self.print_immediately:
            self.print_immediately = True
            row = self._build_row(fields, update_widths=True)
            print(self._row_str(self.header))
        else:
            row = self._build_row(fields, update_widths=False)
        print(self._row_str(row))

    def write(self) -> None:
        """Signals that no more rows will be added."""
        if not self.print_immediately:
            # The header was never printed. Do it now, since we are expected to
            # print a blank table.
            print(self._row_str(self.header))


def print_dictionary(dictionary: Dict[str, Any]) -> None:
    """
    Align and print the data

    :param dictionary: dictionary to print
    :returns: None
    """
    lcol_length = 10
    for title in dictionary:
        lcol_length = max(len(title), lcol_length)

    for title in dictionary:
        print(f"{title.ljust(lcol_length)}: {dictionary[title]}")
