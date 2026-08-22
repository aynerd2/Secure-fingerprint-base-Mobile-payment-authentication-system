#!/usr/bin/env python3
"""
Collect and rename release screenshots into screenshots/.

The raw captures in SFMPASApp/screenshots/ are named t1..t10, which says nothing
about what they show. This maps the best of them onto the stable filenames the
README references, and reports honestly on the ones that do not exist yet rather
than inventing placeholders.

Each mapping below was chosen by inspecting the images, and the reason is
recorded so a future capture session can judge whether a replacement is better.

    python collect_screenshots.py            # copy what exists, report the rest
    python collect_screenshots.py --check    # report only, copy nothing
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEST = ROOT / "screenshots"


def find_source() -> Path | None:
    """
    Locate the raw captures.

    The folder has been renamed at least once during development, so rather than
    hardcoding one path we check the known candidates and then fall back to
    searching for the t1..t10 naming.
    """
    candidates = [
        ROOT / "SFMPASApp" / "screenshots",
        ROOT / "SFMPASApp" / "New folder",
        ROOT / "raw_screenshots",
    ]
    for c in candidates:
        if c.is_dir() and any(c.glob("t*.jpg")):
            return c
    for c in sorted((ROOT / "SFMPASApp").glob("*/")):
        if c.is_dir() and any(c.glob("t*.jpg")):
            return c
    return None


SOURCE = find_source()

# target filename -> (source file or None, why this one)
MAPPING: dict[str, tuple[str | None, str]] = {
    "home_screen.jpg": (
        "t6.jpg",
        "Clean Home: full 5,000,000 balance, Tier 1 chip, and all four actions "
        "including Reset Balance. No history rows cluttering the layout.",
    ),
    "authentication_genuine.jpg": (
        "t2.jpg",
        "Best genuine flow: Tier 2 at 75,000, liveness 1.000000, all steps PASS, "
        "and a REAL signed assertion (MEQCICADiTXYr...) rather than the unsigned "
        "fallback shown in t1/t8.",
    ),
    "results_screen.jpg": (
        "t10.jpg",
        "Transaction history with four authorised payments spanning Tier 1, 2 "
        "and 3, each showing its liveness score. Best single view of results.",
    ),
    # ---- not yet captured -------------------------------------------------
    "registration_screen.jpg": (
        None,
        "No capture exists. Screen 1: name, phone, occupation radio buttons, "
        "Register Fingerprint button.",
    ),
    "payment_screen.jpg": (
        None,
        "No capture exists. Screen 3 with an amount entered so the CBN tier card "
        "is visible — 75,000 shows Tier 2 nicely.",
    ),
    "authentication_attack.jpg": (
        None,
        "No capture exists. Screen 4 with 'Simulate presentation attack' ON at "
        "Tier 2 or 3: red ATTACK, score ~0.000016, Payment Rejected. Every "
        "existing capture has the switch OFF.",
    ),
}

# Screenshots that show the account holder's phone number on screen.
CONTAINS_PII = {"home_screen.jpg", "results_screen.jpg"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="report status without copying")
    args = ap.parse_args()

    if SOURCE is None or not SOURCE.is_dir():
        print("ERROR: could not find the raw captures (looked for a folder "
              "under SFMPASApp/ containing t1.jpg .. t10.jpg).")
        return 1

    if not args.check:
        DEST.mkdir(exist_ok=True)

    copied: list[str] = []
    missing: list[tuple[str, str]] = []

    print(f"source : {SOURCE}")
    print(f"target : {DEST}\n")

    for target, (source_name, reason) in MAPPING.items():
        if source_name is None:
            missing.append((target, reason))
            print(f"  [ MISSING ] {target}")
            continue

        src = SOURCE / source_name
        if not src.is_file():
            missing.append((target, f"expected source {source_name} not found"))
            print(f"  [ MISSING ] {target}  (source {source_name} absent)")
            continue

        if args.check:
            print(f"  [ would copy ] {source_name:<10} -> {target}")
        else:
            shutil.copy2(src, DEST / target)
            size_kb = (DEST / target).stat().st_size / 1024
            print(f"  [    OK    ] {source_name:<10} -> {target}  ({size_kb:,.0f} KB)")
        copied.append(target)

    print(f"\n{len(copied)} of {len(MAPPING)} screenshots available.")

    if missing:
        print("\n" + "=" * 74)
        print("  STILL TO CAPTURE")
        print("=" * 74)
        for target, reason in missing:
            print(f"\n  {target}")
            print(f"    {reason}")
        print("""
  To capture, put the app on that screen and run:

      adb exec-out screencap -p > registration_screen.png

  then convert to .jpg and drop it in screenshots/. Or take a normal
  screenshot on the handset and copy it across.
""")

    pii = [t for t in copied if t in CONTAINS_PII]
    if pii and not args.check:
        # These captures carry a real phone number. Copying re-introduces the
        # un-redacted originals, so redaction is chained here rather than left
        # as a step someone can forget on a later run.
        print("\n" + "=" * 74)
        print("  PRIVACY — redacting phone number")
        print("=" * 74)
        print(f"  affected: {', '.join(pii)}\n")
        try:
            import redact_screenshots
            rc = redact_screenshots.main()
            if rc != 0:
                print("\n  WARNING: redaction reported a problem. Do NOT publish "
                      "these files until it is resolved.")
                return rc
        except Exception as exc:  # noqa: BLE001
            print(f"  ERROR: could not run redact_screenshots.py ({exc}).")
            print("  Do NOT publish these files — they still show the number.")
            return 1
    elif pii:
        print(f"\n  NOTE: {', '.join(pii)} contain a phone number; "
              f"redact_screenshots.py would be run on a real copy.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
