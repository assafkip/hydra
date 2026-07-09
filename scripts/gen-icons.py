#!/usr/bin/env python3
"""rel-pwa: generate the maskable PWA icons (committed as public/icon-192.png + icon-512.png).

Reproducible recipe — a teal (#0F766E, the app --accent) rounded square filling the whole canvas
(so platform masking never clips), with a white lowercase "k" centered inside the maskable safe zone.
Run: python3 scripts/gen-icons.py
"""
from PIL import Image, ImageDraw, ImageFont
import os

TEAL = (15, 118, 110, 255)   # --accent #0F766E
WHITE = (255, 255, 255, 255)
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(HERE, "public")


def font(size):
    for path in (
        "/System/Library/Fonts/SFNSRounded.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
        "/Library/Fonts/Arial.ttf",
    ):
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except Exception:
                pass
    return ImageFont.load_default()


def make(size):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # full-bleed rounded square (maskable: the teal fills the whole canvas)
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=int(size * 0.22), fill=TEAL)
    # the "k" mark, sized to the maskable safe zone (~62% of the canvas)
    f = font(int(size * 0.62))
    text = "k"
    box = d.textbbox((0, 0), text, font=f)
    w, h = box[2] - box[0], box[3] - box[1]
    d.text(((size - w) / 2 - box[0], (size - h) / 2 - box[1]), text, font=f, fill=WHITE)
    return img


for s in (192, 512):
    make(s).save(os.path.join(OUT, f"icon-{s}.png"))
    print(f"wrote public/icon-{s}.png")
