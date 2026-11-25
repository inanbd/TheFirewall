"""
Renders country flags for the app from the flag-icons package (MIT, https://github.com/lipis/flag-icons).

    npm pack flag-icons && tar -xzf flag-icons-*.tgz        # gives ./package/flags/4x3/*.svg
    pip install cairosvg pillow
    python3 build/generate-flags.py ./package/flags/4x3

Writes src/TheFirewall.App/Assets/Flags/<code>.png (40x30, shown at 20x15) for every country in Countries.cs.
"""
import io
import os
import re
import sys

import cairosvg
from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "src", "TheFirewall.App", "Assets", "Flags")
COUNTRIES = os.path.join(ROOT, "src", "TheFirewall.Core", "Geo", "Countries.cs")
WIDTH, HEIGHT = 40, 30


def country_codes():
    text = open(COUNTRIES, encoding="utf-8").read()
    codes = set()
    for match in re.finditer(r'\("([A-Za-z ]+)", "([A-Z ]+)"\)', text):
        codes.update(match.group(2).split())
    return sorted(codes)


def main(svg_dir):
    os.makedirs(OUT, exist_ok=True)
    missing = []
    for code in country_codes():
        svg = os.path.join(svg_dir, code.lower() + ".svg")
        if not os.path.exists(svg):
            missing.append(code)
            continue
        png = cairosvg.svg2png(url=svg, output_width=WIDTH * 4, output_height=HEIGHT * 4)
        image = Image.open(io.BytesIO(png)).convert("RGBA").resize((WIDTH, HEIGHT), Image.LANCZOS)
        image = image.convert("P", palette=Image.ADAPTIVE, colors=64)
        image.save(os.path.join(OUT, code.lower() + ".png"), optimize=True)
    print(f"{len(country_codes()) - len(missing)} flags written to {OUT}")
    if missing:
        print("No flag for: " + ", ".join(missing))


if __name__ == "__main__":
    main(sys.argv[1])
