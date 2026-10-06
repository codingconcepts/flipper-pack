#!/usr/bin/env python3
"""Generate the 10x10 1-bit FAP icons for the three NFC apps.

Drawing them as text grids keeps them editable; at this size a paint program is
more trouble than it is worth. '#' is a lit pixel -- the SDK's png2xbm sets a
bit wherever the source pixel is black.
"""
from PIL import Image

ICONS = {
    # Card outline with a question mark: identify what this card is.
    "nfc_ident/nfc_ident.png": """
        ##########
        #..####..#
        #.##..##.#
        #.....##.#
        #....##..#
        #...##...#
        #........#
        #...##...#
        #........#
        ##########
    """,
    # Card outline with an arrow through it: rewrite one variant as another.
    "nfc_convert/nfc_convert.png": """
        ##########
        #........#
        #........#
        #....#...#
        #.....#..#
        #.######.#
        #.....#..#
        #....#...#
        #........#
        ##########
    """,
    # Two offset cards: hold one against the other.
    "nfc_compare/nfc_compare.png": """
        ..#######.
        ..#.....#.
        ..#.....#.
        ..#.....#.
        #######.#.
        #.....#.#.
        #.....#.#.
        #.....###.
        #.....#...
        #######...
    """,
}

for path, art in ICONS.items():
    rows = [line.strip() for line in art.strip().splitlines()]
    assert len(rows) == 10, f"{path}: {len(rows)} rows"
    assert all(len(r) == 10 for r in rows), f"{path}: bad row width"

    image = Image.new("1", (10, 10), 1)
    for y, row in enumerate(rows):
        for x, char in enumerate(row):
            if char == "#":
                image.putpixel((x, y), 0)
    image.save(path)
    print(f"wrote {path}")
