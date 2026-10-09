#!/usr/bin/env python3
"""Renders neon-city.jpg, the wallpaper of the neon example: a synthwave sun behind a city
skyline, over a glowing grid. Original artwork, generated here (seeded, so it renders the
same picture every time).

    python make-wallpaper.py [out.jpg] [width] [height]

Needs Pillow and numpy.
"""
import random
import sys

import numpy as np
from PIL import Image, ImageDraw, ImageFilter

OUT = sys.argv[1] if len(sys.argv) > 1 else "neon-city.jpg"
W = int(sys.argv[2]) if len(sys.argv) > 2 else 2560
H = int(sys.argv[3]) if len(sys.argv) > 3 else 1440
HORIZON = int(H * 0.64)
rng = random.Random(2077)

PINK = (255, 42, 109)
CYAN = (5, 217, 232)
VIOLET = (130, 60, 255)
AMBER = (255, 190, 60)


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def vertical_gradient(w, h, stops):
    """stops: [(position 0..1, (r, g, b)), ...] top to bottom."""
    ys = np.linspace(0, 1, h)
    img = np.zeros((h, w, 3), dtype=np.float32)
    for c in range(3):
        img[:, :, c] = np.interp(ys, [p for p, _ in stops], [col[c] for _, col in stops])[:, None]
    return img


# Sky: deep night at the top, violet, then a hot pink haze at the horizon.
sky = vertical_gradient(W, H, [
    (0.00, (4, 2, 18)),
    (0.30, (22, 6, 52)),
    (0.52, (74, 14, 96)),
    (0.64, (190, 36, 120)),
    (0.66, (40, 6, 50)),
    (1.00, (6, 2, 14)),
])
canvas = Image.fromarray(sky.clip(0, 255).astype(np.uint8), "RGB")
draw = ImageDraw.Draw(canvas)

# Stars, fading toward the horizon.
for _ in range(900):
    x, y = rng.randrange(W), int(rng.random() ** 1.8 * HORIZON * 0.75)
    b = rng.randint(90, 255) * (1 - y / HORIZON)
    r = rng.choice([1, 1, 1, 2])
    draw.ellipse([x, y, x + r, y + r], fill=(int(b * 0.9), int(b * 0.85), int(b)))

# The sun: a big disc, amber to pink, cut by the horizontal bands of a synthwave sun.
sun_r = int(H * 0.27)
cx, cy = W // 2, HORIZON - int(sun_r * 0.35)
sun = Image.new("RGBA", (W, H), (0, 0, 0, 0))
sd = ImageDraw.Draw(sun)
band_top = cy - int(sun_r * 0.5)
for y in range(cy - sun_r, min(cy + sun_r, HORIZON)):
    t = (y - (cy - sun_r)) / (2 * sun_r)
    half = int((sun_r ** 2 - (y - cy) ** 2) ** 0.5)
    if y >= band_top:
        # Bands that thicken toward the horizon.
        depth = (y - band_top) / max(1, HORIZON - band_top)
        period = int(sun_r * 0.13)
        gap = int(period * (0.12 + depth * 0.5))
        if (y - band_top) % period < gap:
            continue
    sd.line([(cx - half, y), (cx + half, y)], fill=lerp(AMBER, PINK, t) + (255,))
glow = sun.filter(ImageFilter.GaussianBlur(H * 0.06))
canvas.paste(glow, (0, 0), glow)
canvas.paste(glow, (0, 0), glow)
canvas.paste(sun, (0, 0), sun)


def skyline(layer_color, base, min_h, max_h, min_w, max_w, window_odds, seed, signs):
    r = random.Random(seed)
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    lights = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ld, gd = ImageDraw.Draw(layer), ImageDraw.Draw(lights)
    x = -r.randint(0, max_w)
    while x < W:
        bw = r.randint(min_w, max_w)
        bh = r.randint(min_h, max_h)
        if abs(x + bw / 2 - W / 2) < W * 0.15:
            bh = int(bh * 0.28)  # keep the sun in view
        top = base - bh
        ld.rectangle([x, top, x + bw, base], fill=layer_color)
        if r.random() < 0.35:  # an antenna or a setback
            ax = x + r.randint(4, max(5, bw - 4))
            ld.line([(ax, top), (ax, top - r.randint(20, 90))], fill=layer_color, width=3)
            gd.ellipse([ax - 3, top - 95, ax + 3, top - 89], fill=PINK + (255,))
        # Windows
        wx, wy = max(6, bw // 14), max(8, bh // 40)
        for yy in range(top + 10, base - 6, wy * 2):
            for xx in range(x + 6, x + bw - wx - 4, wx * 2):
                if r.random() < window_odds:
                    c = r.choice([CYAN, CYAN, PINK, AMBER, (180, 200, 255)])
                    gd.rectangle([xx, yy, xx + wx - 2, yy + wy - 2], fill=c + (r.randint(140, 255),))
        # Vertical neon signs
        if signs and r.random() < 0.18 and bh > H * 0.18:
            c = r.choice([PINK, CYAN, VIOLET])
            sx = x + r.randint(6, max(7, bw - 20))
            sy = top + r.randint(20, 80)
            gd.rectangle([sx, sy, sx + 12, sy + r.randint(90, 220)], fill=c + (255,))
        x += bw + r.randint(0, 14)
    halo = lights.filter(ImageFilter.GaussianBlur(6))
    layer.alpha_composite(halo)
    layer.alpha_composite(lights)
    return layer


back = skyline((28, 8, 48, 255), HORIZON, int(H * 0.12), int(H * 0.36), 60, 170, 0.18, 7, False)
front = skyline((10, 3, 20, 255), HORIZON + 4, int(H * 0.08), int(H * 0.46), 90, 260, 0.28, 11, True)
canvas = canvas.convert("RGBA")
canvas.alpha_composite(back)
canvas.alpha_composite(front)

# The grid: lines converging on the vanishing point, horizontals bunching toward the horizon.
grid = Image.new("RGBA", (W, H), (0, 0, 0, 0))
gd = ImageDraw.Draw(grid)
floor_top = HORIZON + 6
for i in range(-40, 41):
    x_far = W / 2 + i * W * 0.012
    x_near = W / 2 + i * W * 0.11
    gd.line([(x_far, floor_top), (x_near, H)], fill=PINK + (230,), width=3)
z = 1.0
while True:
    y = floor_top + (H - floor_top) / z * 0.9
    if y < floor_top + 2:
        break
    if y <= H:
        gd.line([(0, y), (W, y)], fill=CYAN + (200,), width=2)
    z *= 1.32
fade = Image.linear_gradient("L").resize((W, H - floor_top))
mask = Image.new("L", (W, H), 0)
mask.paste(fade, (0, floor_top))
grid.putalpha(Image.composite(grid.getchannel("A"), Image.new("L", (W, H), 0), mask))
grid_glow = grid.filter(ImageFilter.GaussianBlur(8))
canvas.alpha_composite(grid_glow)
canvas.alpha_composite(grid)

# The sun's reflection on the floor: its glow, mirrored and faint.
refl = glow.crop((0, HORIZON - sun_r, W, HORIZON)).transpose(Image.FLIP_TOP_BOTTOM)
fade = Image.linear_gradient("L").rotate(180).resize(refl.size)
refl.putalpha(Image.composite(refl.getchannel("A").point(lambda a: int(a * 0.5)), Image.new("L", refl.size, 0), fade))
canvas.alpha_composite(refl, (0, HORIZON + 6))

# A thin bright horizon line, and faint scanlines over everything.
hl = Image.new("RGBA", (W, H), (0, 0, 0, 0))
ImageDraw.Draw(hl).line([(0, HORIZON + 5), (W, HORIZON + 5)], fill=(255, 120, 200, 255), width=3)
canvas.alpha_composite(hl.filter(ImageFilter.GaussianBlur(5)))
canvas.alpha_composite(hl)
scan = Image.new("RGBA", (W, H), (0, 0, 0, 0))
sd = ImageDraw.Draw(scan)
for y in range(0, H, 4):
    sd.line([(0, y), (W, y)], fill=(0, 0, 0, 28))
canvas.alpha_composite(scan)

canvas.convert("RGB").save(OUT, "JPEG", quality=88, optimize=True, progressive=True)
print(f"wrote {OUT} ({W}x{H})")
