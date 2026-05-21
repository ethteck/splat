## Writing custom segment handler

The following list contains examples of custom segments:

- [RNC](https://github.com/mkst/sssv/blob/master/tools/splat_ext/rnc.py)
- [Vtx](https://github.com/mkst/sssv/blob/master/tools/splat_ext/sssv_vtx.py)
- [Multiple](https://github.com/pmret/papermario/tree/main/tools/splat_ext)

## Visualizing the relationships between symbols

This section describes how to graph relationships between symbols inside a splat segment, which can help to split sections and also pair them together (in particular, splitting and pairing asm and rodata sections).

Prerequisite: enable the [`dump_symbols`](Configuration.md#dump_symbols) and [`dump_symbols_references`](Configuration.md#dump_symbols_references) options, and run `splat split`.

You can then parse `.splat/splat_symbols.csv` and use it to gain insights on how the sections are laid out.

For example, take the following script:

<details>

```py
#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# graph_cross_sections_refs.py

import argparse
import csv
import dataclasses


@dataclasses.dataclass(frozen=True)
class Sym:
    vram_start: int
    name: str
    type: str
    segment: str
    subsegment: str
    subsegment_type: str
    referenced_by: tuple[str, ...]


syms = list[Sym]()

with open(".splat/splat_symbols.csv") as f:
    for row in csv.DictReader(f):
        if row["referenced_by"] == "":
            referenced_by = []
        else:
            referenced_by = row["referenced_by"].split("|")
        syms.append(
            Sym(
                int(row["vram_start"], 16),
                row["name"],
                row["type"],
                row["segment"],
                row["subsegment"],
                row["subsegment_type"],
                tuple(referenced_by),
            )
        )

sym_by_name = {_sym.name: _sym for _sym in syms}

parser = argparse.ArgumentParser()
parser.add_argument("segment")
parser.add_argument(
    "--section",
    nargs="+",
    help=(
        "only show this section besides text,"
        " eg --section rodata will only show text and rodata"
    ),
)
args = parser.parse_args()

section_by_subsegment_type = {
    "asm": "text",
    "c": "text",
    "textbin": "text",
    "hasm": "text",
    "data": "data",
    "rodata": "rodata",
    ".rodata": "rodata",
    "bss": "bss",
}

syms_by_section: dict[str, list[Sym]] = {}
for sym in syms:
    if sym.segment != args.segment:
        continue
    section = section_by_subsegment_type.get(sym.subsegment_type)
    assert section is not None, sym
    syms_by_section.setdefault(section, []).append(sym)

text_subsegments = sorted({_sym.subsegment for _sym in syms_by_section["text"]})
color_by_subsegment: dict[str, str] = {}
for subsegment in text_subsegments:
    h = (len(color_by_subsegment) * 0.7) % 1
    color_by_subsegment[subsegment] = f"{h} 1 1"

if args.section:
    for section in list(syms_by_section.keys()):
        if section != "text" and section not in args.section:
            del syms_by_section[section]

section_by_sym_name = {
    _sym.name: _section for _section, _syms in syms_by_section.items() for _sym in _syms
}

vram_start_by_section: dict[str, int] = {}
for section, section_syms in syms_by_section.items():
    vram_start_by_section[section] = min(_s.vram_start for _s in section_syms)


colw = 10
x_by_section = {
    "text": 0 * colw,
    "data": 1 * colw,
    "rodata": 2 * colw,
    "bss": 3 * colw,
}


def gprint(l: str):
    print(l)


gprint("digraph {")

for section, section_syms in syms_by_section.items():
    section_vram_start = vram_start_by_section[section]
    x = x_by_section[section]
    filtered_syms: list[Sym] = []
    for sym in sorted(section_syms, key=lambda sym: sym.vram_start):
        if sym.type in {"label", "jtbl_label"}:
            continue
        filtered_syms.append(sym)
    cur_subsegment = None
    i = 0
    dy = 0
    for sym in filtered_syms:
        if cur_subsegment != sym.subsegment:
            if cur_subsegment is not None:
                gprint("}")
            cur_subsegment = sym.subsegment
            gprint(f"subgraph cluster_{cur_subsegment}_{section} " "{")
            y = -i / len(filtered_syms) * 100 + dy - 0.2
            gprint(f'"{cur_subsegment} {section}"' " [" f' pos = "{x},{y}!"' f' color="none"' " ]")
            dy -= 0.8
        assert cur_subsegment is not None
        if 0:
            # y = vram position
            y = -(sym.vram_start - section_vram_start) / 500
        y = -i / len(filtered_syms) * 100 + dy
        i += 1
        color = None
        if section == "text":
            color = color_by_subsegment[cur_subsegment]
        elif section == "rodata":
            if sym.type == "jtbl":
                color = "magenta"
        gprint(
            f'"{sym.name}"'
            " ["
            f' pos = "{x},{y}!"'
            + (f' color="{color}"' if color is not None else "")
            + " ]"
        )
    if cur_subsegment is not None:
        gprint("}")

for section, section_syms in syms_by_section.items():
    for sym in section_syms:
        for sym_ref_by in sym.referenced_by:
            if (
                # ignore references from outside the segment
                sym_ref_by in section_by_sym_name
                # ignore same-section references
                and section_by_sym_name[sym_ref_by] != section
                # only show
                and (
                    # references from text
                    section_by_sym_name[sym_ref_by] == "text"
                    # or references from data to rodata
                    or (
                        section_by_sym_name[sym_ref_by] == "data"
                        and section_by_subsegment_type[sym.subsegment_type] == "rodata"
                    )
                )
            ):
                try:
                    color = color_by_subsegment[sym_by_name[sym_ref_by].subsegment]
                except KeyError:
                    color = "black"
                gprint(f'"{sym_ref_by}" -> "{sym.name}"' f' [ color = "{color}" ]')

gprint("}")
```

</details>

This script takes as input the name of a splat segment, and produces a graph in dot language.
Optionally, it can also be passed for example `--section rodata` to restrict the visualization to text and rodata sections.

To render the script output, first save its output to a file, for example:

```sh
./graph_cross_sections_refs.py my_segment --section rodata > my_segment.dot
```

Then use graphviz to render it to svg (for example):

```sh
neato -Tsvg -O my_segment.dot
```

(on Ubuntu you can install graphviz with `apt install graphviz`)

You can then open the `my_segment.dot.svg` file for viewing.

The produced graph is laid out in columns: from left to right, the columns correspond to the text, data, rodata and bss sections. (note: if you passed e.g. `--section rodata` to the script, only text and rodata will be present)

Symbols are further clustered by subsegments, indicated by black rectangles, and the name of the subsegment is indicated at the top of each cluster.
Each text subsegment is colored differently.

A suggested workflow based on this visualization is then to
0. Pick a segment of interest
1. Run `splat split`
2. Generate and render a graph
3. Refine the segment's subsegments splits and pairing
4. Iterate from step 1 again until satisfied
