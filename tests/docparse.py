"""Split `docs/LIMITATIONS.md` into its numbered entries.

One parser, imported wherever a check needs to read an entry rather than the
whole file. Two copies of an entry parser is one edit away from two checks that
disagree about what an entry is.
"""

from __future__ import annotations

import re

#: A numbered limitation entry opens with `**N.` at the start of a line.
LIMITATION_ENTRY = re.compile(r"^\*\*(\d+)\.")


def limitation_entries(text: str) -> dict[int, str]:
    """Number -> the whole text of that numbered entry in `docs/LIMITATIONS.md`.

    An entry runs from its `**N.` line to the next one or to the next section
    heading, so a check on "does the entry say X" reads the entry rather than
    the file.
    """
    lines = text.splitlines()
    starts = [(index, int(match.group(1))) for index, line in enumerate(lines)
              if (match := LIMITATION_ENTRY.match(line))]
    entries: dict[int, str] = {}
    for position, (start, number) in enumerate(starts):
        end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        for index in range(start + 1, end):
            if lines[index].startswith("## "):
                end = index
                break
        entries[number] = "\n".join(lines[start:end])
    return entries
