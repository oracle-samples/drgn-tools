# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import sys
from typing import Any
from typing import Dict
from typing import List
from typing import Optional


def print_row(fields: List[Any], col_widths: List[int]):
    """
    Print a single row of a table, given pre-determined column widths

    Note that this doesn't guarantee that the width of every field in the row
    will be less than the width of the column: in that case, the field's full
    contents will be printed and columns will be misaligned. For guaranteed
    aligned columns, see print_table(), or be very careful about your column
    widths.

    :param fields: a list of fields to print
    :param col_widths: the width of each field (not including spaces)
    """
    print(
        "  ".join(
            str(val) if w <= 0 else str(val).ljust(w)
            for val, w in zip(fields, col_widths)
        )
    )


def print_table(
    fields: List[List[Any]],
    outfile: Optional[str] = None,
    report: bool = False,
) -> None:
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

    out = sys.stdout
    if outfile and report:
        out = open(outfile, "a")
        print("\n", file=out)
    elif outfile:
        out = open(outfile, "w")

    for entry in fields:
        print(
            "".join(
                str(val).ljust(col_width + 2)
                for (val, col_width) in zip(entry, col_widths)
            ),
            file=out,
        )

    if outfile:
        out.close()


def print_dictionary(
    dictionary: Dict[str, Any],
    outfile: Optional[str] = None,
    report: bool = False,
) -> None:
    """
    Align and print the data

    :param dictionary: dictionary to print
    :param outfile: A file to write the output to.
    :param report: Open the file in append mode.
    :returns: None
    """
    lcol_length = 10
    for title in dictionary:
        lcol_length = max(len(title), lcol_length)

    out = sys.stdout
    if outfile and report:
        out = open(outfile, "a")
        print("\n", file=out)
    elif outfile:
        out = open(outfile, "w")

    for title in dictionary:
        print(
            f"{title.ljust(lcol_length)}: {dictionary[title]}",
            file=out,
        )

    if outfile:
        out.close()
