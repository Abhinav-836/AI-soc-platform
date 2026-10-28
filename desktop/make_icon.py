"""Draw the app icon (shield + radar) -> desktop/assets/app.ico. Generated at build time."""
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent / "assets"


def draw(size: int = 256) -> Image.Image:
    s = size / 256
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, size - 1, size - 1], radius=int(56 * s), fill=255)
    bg = Image.new("RGBA", (size, size), (8, 14, 12, 255))
    img.paste(bg, (0, 0), mask)
    d = ImageDraw.Draw(img)
    shield = [(128, 30), (210, 62), (204, 150), (128, 226), (52, 150), (46, 62)]
    d.polygon([(x * s, y * s) for x, y in shield], outline=(0, 230, 118, 255), width=max(int(12 * s), 2))
    for r in (24, 48):
        d.ellipse([(128 - r) * s, (128 - r) * s, (128 + r) * s, (128 + r) * s], outline=(0, 230, 118, 200),
                  width=max(int(6 * s), 1))
    d.line([(128 * s, 128 * s), (168 * s, 92 * s)], fill=(0, 230, 118, 255), width=max(int(8 * s), 2))
    return img


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    img = draw()
    img.save(OUT / "app.png")
    img.save(OUT / "app.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print(f"Icon written to {OUT}")


if __name__ == "__main__":
    main()
