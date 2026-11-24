"""Generates TheFirewall's icons and installer artwork. Run: python3 build/generate-icons.py"""
import os
from PIL import Image, ImageDraw, ImageFilter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = os.path.join(ROOT, "src", "TheFirewall.App", "Assets")
INSTALLER = os.path.join(ROOT, "installer", "TheFirewall.Installer", "Resources")
os.makedirs(ASSETS, exist_ok=True)
os.makedirs(INSTALLER, exist_ok=True)

SS = 4  # supersampling factor


def bezier(p0, p1, p2, steps=40):
    pts = []
    for i in range(steps + 1):
        t = i / steps
        x = (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t ** 2 * p2[0]
        y = (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t ** 2 * p2[1]
        pts.append((x, y))
    return pts


def shield_points(size, inset=0.0):
    s = size
    m = inset * s
    top = 0.07 * s + m
    left = 0.13 * s + m
    right = 0.87 * s - m
    shoulder = 0.18 * s + m
    mid = 0.50 * s
    bottom = 0.95 * s - m * 1.3
    pts = []
    pts += bezier((mid, top), (mid + 0.20 * s, shoulder - 0.02 * s), (right, shoulder))
    pts += [(right, 0.50 * s)]
    pts += bezier((right, 0.50 * s), (right - 0.02 * s, 0.80 * s), (mid, bottom))
    pts += bezier((mid, bottom), (left + 0.02 * s, 0.80 * s), (left, 0.50 * s))
    pts += [(left, shoulder)]
    pts += bezier((left, shoulder), (mid - 0.20 * s, shoulder - 0.02 * s), (mid, top))
    return pts


def gradient(size, top_color, bottom_color):
    img = Image.new("RGBA", (size, size))
    d = ImageDraw.Draw(img)
    for y in range(size):
        t = y / max(1, size - 1)
        c = tuple(int(top_color[i] + (bottom_color[i] - top_color[i]) * t) for i in range(3)) + (255,)
        d.line([(0, y), (size, y)], fill=c)
    return img


def draw_icon(size, top_color, bottom_color, bricks=True, small=False):
    big = size * SS
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).polygon(shield_points(big), fill=255)

    fill = gradient(big, top_color, bottom_color)
    icon = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    icon.paste(fill, (0, 0), mask)

    # Subtle top highlight
    highlight = Image.new("L", (big, big), 0)
    ImageDraw.Draw(highlight).polygon(shield_points(big, 0.045), fill=255)
    hl = Image.new("RGBA", (big, big), (255, 255, 255, 0))
    hd = ImageDraw.Draw(hl)
    for y in range(int(big * 0.5)):
        alpha = int(46 * (1 - y / (big * 0.5)))
        hd.line([(0, y), (big, y)], fill=(255, 255, 255, alpha))
    icon = Image.alpha_composite(icon, Image.composite(hl, Image.new("RGBA", (big, big), (0, 0, 0, 0)), highlight))

    if bricks:
        wall = Image.new("RGBA", (big, big), (0, 0, 0, 0))
        wd = ImageDraw.Draw(wall)
        rows = 3
        x0, x1 = 0.29 * big, 0.71 * big
        y0 = (0.36 if small else 0.34) * big
        row_h = (0.15 if small else 0.10) * big
        gap = (0.045 if small else 0.03) * big
        if small:
            rows = 2
        width = x1 - x0
        for r in range(rows):
            y = y0 + r * (row_h + gap)
            offset = 0 if r % 2 == 0 else -0.5
            count = 2 if small else 3
            brick_w = (width - gap * (count - 1)) / count
            positions = []
            for i in range(-1, count + 1):
                bx = x0 + (i + offset) * (brick_w + gap)
                positions.append((max(bx, x0), min(bx + brick_w, x1)))
            for (a, b) in positions:
                if b - a > gap:
                    wd.rounded_rectangle([a, y, b, y + row_h], radius=row_h * 0.22, fill=(255, 255, 255, 240))
        # keep the wall inside the shield
        inner = Image.new("L", (big, big), 0)
        ImageDraw.Draw(inner).polygon(shield_points(big, 0.07), fill=255)
        wall.putalpha(Image.composite(wall.getchannel("A"), Image.new("L", (big, big), 0), inner))
        icon = Image.alpha_composite(icon, wall)

    return icon.resize((size, size), Image.LANCZOS)


def save_ico(path, top, bottom, sizes):
    images = [draw_icon(s, top, bottom, small=s <= 24) for s in sizes]
    images[-1].save(path, format="ICO", sizes=[(s, s) for s in sizes], append_images=images[:-1])


BLUE_TOP, BLUE_BOTTOM = (37, 99, 235), (13, 148, 136)
GREEN_TOP, GREEN_BOTTOM = (22, 163, 74), (13, 148, 136)
AMBER_TOP, AMBER_BOTTOM = (245, 158, 11), (217, 119, 6)
GREY_TOP, GREY_BOTTOM = (148, 163, 184), (100, 116, 139)
RED_TOP, RED_BOTTOM = (239, 68, 68), (185, 28, 28)

ALL = [16, 20, 24, 32, 40, 48, 64, 128, 256]
TRAY = [16, 20, 24, 32, 40, 48, 64]

save_ico(os.path.join(ASSETS, "TheFirewall.ico"), BLUE_TOP, BLUE_BOTTOM, ALL)
save_ico(os.path.join(ASSETS, "TrayProtected.ico"), GREEN_TOP, GREEN_BOTTOM, TRAY)
save_ico(os.path.join(ASSETS, "TrayPaused.ico"), AMBER_TOP, AMBER_BOTTOM, TRAY)
save_ico(os.path.join(ASSETS, "TrayOffline.ico"), GREY_TOP, GREY_BOTTOM, TRAY)
save_ico(os.path.join(ASSETS, "TrayAlert.ico"), RED_TOP, RED_BOTTOM, TRAY)
draw_icon(256, BLUE_TOP, BLUE_BOTTOM).save(os.path.join(ASSETS, "Logo.png"))

# WiX installer artwork (24-bit BMP)
banner = Image.new("RGB", (493, 58), (255, 255, 255))
logo = draw_icon(44, BLUE_TOP, BLUE_BOTTOM)
banner.paste(logo, (493 - 44 - 10, 7), logo)
banner.save(os.path.join(INSTALLER, "Banner.bmp"))

dialog = Image.new("RGB", (493, 312), (255, 255, 255))
side = gradient(164, BLUE_TOP, BLUE_BOTTOM).resize((164, 312)).convert("RGB")
dialog.paste(side, (0, 0))
big_logo = draw_icon(112, (255, 255, 255), (226, 232, 240), bricks=False)
dialog.paste(big_logo, (26, 90), big_logo)
dialog.save(os.path.join(INSTALLER, "Dialog.bmp"))
print("icons written")
