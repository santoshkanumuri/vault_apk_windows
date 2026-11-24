"""Writes the MSIX icon assets of Nuvori for Windows into src-tauri/icons/msix/.

    python scripts/build-msix-icons.py

The taskbar, Start and the title bar show Square44x44Logo. Without `altform-unplated` versions,
Windows draws it on a plate filled with the user's accent color (a colored square behind the
lock). The `targetsize-N_altform-unplated` and `_altform-lightunplated` files are what Windows
shows instead, like other Store apps. scripts/package-msix.ps1 copies this folder into the
package and indexes it with makepri into resources.pri, which Windows needs to find them.

Source: app-icon.png (1254 px). Faint glow pixels around the padlock are dropped, the padlock is
cropped to its edges, then padded to a square for each kind of asset.
"""
import pathlib

from PIL import Image

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "app-icon.png"
OUT = ROOT / "src-tauri" / "icons" / "msix"

TARGET_SIZES = [16, 20, 24, 30, 32, 36, 40, 48, 60, 64, 72, 80, 96, 256]
SCALES = {100: 1.0, 125: 1.25, 150: 1.5, 200: 2.0, 400: 4.0}


def padlock() -> Image.Image:
    image = Image.open(SOURCE).convert("RGBA")
    # The source has a near-invisible glow; keep only pixels that are clearly part of the padlock.
    alpha = image.getchannel("A").point(lambda a: 0 if a < 40 else a)
    image.putalpha(alpha)
    return image.crop(alpha.point(lambda a: 255 if a > 128 else 0).getbbox())


def square(content: Image.Image, size: int, padding: float) -> Image.Image:
    """[content] centered in a transparent [size] square, leaving [padding] of the side free."""
    inner = max(1, round(size * (1 - 2 * padding)))
    scale = inner / max(content.size)
    resized = content.resize((max(1, round(content.width * scale)), max(1, round(content.height * scale))), Image.LANCZOS)
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    canvas.paste(resized, ((size - resized.width) // 2, (size - resized.height) // 2), resized)
    return canvas


def main():
    lock = padlock()
    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("*.png"):
        old.unlink()
    written = 0
    for size in TARGET_SIZES:
        # Plated (on the accent tile), unplated on dark and on light taskbars. The padlock reads on both.
        square(lock, size, 0.16).save(OUT / f"Square44x44Logo.targetsize-{size}.png")
        for altform in ("altform-unplated", "altform-lightunplated"):
            square(lock, size, 0.03 if size >= 32 else 0.0).save(OUT / f"Square44x44Logo.targetsize-{size}_{altform}.png")
        written += 3
    for scale, factor in SCALES.items():
        square(lock, round(44 * factor), 0.16).save(OUT / f"Square44x44Logo.scale-{scale}.png")
        square(lock, round(150 * factor), 0.22).save(OUT / f"Square150x150Logo.scale-{scale}.png")
        square(lock, round(50 * factor), 0.06).save(OUT / f"StoreLogo.scale-{scale}.png")
        written += 3
    print(f"wrote {written} files to {OUT}")


if __name__ == "__main__":
    main()
