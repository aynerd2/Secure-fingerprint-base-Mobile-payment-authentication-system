#!/usr/bin/env python3
"""
Redact the account holder's phone number from release screenshots.

The Home screen renders "<phone> · <occupation>" under the welcome message. The
phone number is real personal data and must not go into a public repository —
git history keeps it even if the file is deleted later.

Region
------
Measured on the 1080x2408 captures, the line sits at y 385-412, with the number
occupying x 55-262 and "· General User" continuing to x ~487. The band below
covers the number with margin and stops before the separator, so the occupation
stays visible — it is not personal data and it is useful context in the README.

Method
------
Mosaic (downsample to a few pixels, then nearest-neighbour back up) followed by
a Gaussian blur. Plain Gaussian blur is a poor redaction for text: the kernel is
known and low-entropy glyphs can be partially recovered by deconvolution. The
mosaic step discards the information first, so the result is irreversible; the
blur only softens the block edges so it reads as a blur rather than a stamp.

Idempotent: re-running on an already-redacted file simply re-blurs flat pixels.

    python redact_screenshots.py            # redact in place
    python redact_screenshots.py --dry-run  # write *_redacted.jpg instead
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from PIL import Image, ImageFilter

ROOT = Path(__file__).resolve().parent
SHOTS = ROOT / "screenshots"

# Screenshots showing the phone number, and the box to destroy.
# (left, top, right, bottom) in pixels, for a 1080x2408 capture.
TARGETS: dict[str, tuple[int, int, int, int]] = {
    "home_screen.jpg": (30, 375, 285, 422),
    "results_screen.jpg": (30, 375, 285, 422),
}

EXPECTED_SIZE = (1080, 2408)
MOSAIC_BLOCKS = 4      # region is reduced to this many blocks across
BLUR_RADIUS = 6.0
JPEG_QUALITY = 95


def redact(image: Image.Image, box: tuple[int, int, int, int]) -> Image.Image:
    left, top, right, bottom = box
    width, height = right - left, bottom - top
    if width <= 0 or height <= 0:
        raise ValueError(f"degenerate box {box}")

    region = image.crop(box)

    # 1. Mosaic — this is the step that actually destroys the glyphs.
    small = region.resize(
        (max(1, MOSAIC_BLOCKS), max(1, round(MOSAIC_BLOCKS * height / width))),
        Image.Resampling.BILINEAR,
    )
    region = small.resize((width, height), Image.Resampling.NEAREST)

    # 2. Soften the block edges so it reads as a blur.
    region = region.filter(ImageFilter.GaussianBlur(radius=BLUR_RADIUS))

    out = image.copy()
    out.paste(region, box)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="write <name>_redacted.jpg instead of overwriting")
    # argv defaults to [] rather than sys.argv so this stays callable as a
    # library from collect_screenshots.py without inheriting its flags.
    args = ap.parse_args(argv if argv is not None else [])

    if not SHOTS.is_dir():
        print(f"ERROR: {SHOTS} not found — run collect_screenshots.py first")
        return 1

    failures = 0
    for name, box in TARGETS.items():
        path = SHOTS / name
        if not path.is_file():
            print(f"  [ SKIP ] {name} — not present")
            continue

        with Image.open(path) as im:
            im = im.convert("RGB")
            if im.size != EXPECTED_SIZE:
                # The box is in absolute pixels; a different capture size would
                # silently redact the wrong area, which is worse than failing.
                print(f"  [ FAIL ] {name} — expected {EXPECTED_SIZE}, got {im.size}. "
                      f"Re-measure the box before redacting this file.")
                failures += 1
                continue
            out = redact(im, box)

        target = path if not args.dry_run else path.with_name(
            f"{path.stem}_redacted{path.suffix}")
        out.save(target, "JPEG", quality=JPEG_QUALITY, subsampling=0)
        kb = target.stat().st_size / 1024
        print(f"  [  OK  ] {name}  box={box}  -> {target.name} ({kb:,.0f} KB)")

    print("\nRedaction is destructive and irreversible — the pixels are gone, "
          "not merely obscured.")
    if not args.dry_run:
        print("Originals in SFMPASApp/screenshots/ are untouched; re-run "
              "collect_screenshots.py to restore.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
