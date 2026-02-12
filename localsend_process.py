#!/usr/bin/env python

import os
import re
import sys
import shutil
import subprocess
from pathlib import Path

# ---- Configuration ----
ROOT_DIR = Path("~/localsend").expanduser()
SCALES = [80, 60, 40, 20, 10]  # percent
# Common image extensions (add/remove as needed)
IMAGE_EXTS = {
    ".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff", ".bmp", ".gif", ".heic", ".avif"
}

# ImageMagick command (prefer "magick", fall back to "convert")
def find_imagemagick_cmd() -> list[str]:
    if shutil.which("magick"):
        return ["magick"]
    if shutil.which("convert"):
        # Older IM installs expose "convert"; note it can conflict with system tools on some distros.
        return ["convert"]
    return []

IM_CMD = find_imagemagick_cmd()

def is_image_file(p: Path) -> bool:
    return p.is_file() and p.suffix.lower() in IMAGE_EXTS

def output_path_for_scale(src: Path, percent: int) -> Path:
    # Preserve suffix; put scale marker before extension
    return src.with_name(f"{src.stem}_{percent}percent{src.suffix}")

def already_done(out: Path) -> bool:
    # Skip if output exists and is non-empty
    return out.exists() and out.is_file() and out.stat().st_size > 0

def run_imagemagick(src: Path, out: Path, percent: int) -> None:
    """
    Create a resized copy and strip identifying metadata.
    - -strip: removes profiles and comments (EXIF/IPTC/XMP, etc.)
    - +profile "*": extra belt-and-suspenders profile removal
    - -define ...: reduce incidental metadata in some formats
    """
    out.parent.mkdir(parents=True, exist_ok=True)

    # Use a temp file then atomic replace, to avoid partially-written outputs.
    tmp_out = out.with_suffix(out.suffix + ".tmp")

    cmd = (
        IM_CMD
        + [
            str(src),
            "-auto-orient",                 # apply EXIF orientation then re-encode
            "-resize", f"{percent}%",       # scale by percentage
            "-strip",                       # remove profiles/comments/metadata
            "+profile", "*",                # remove any remaining profiles
            "-define", "png:exclude-chunks=all",  # reduce embedded chunks/metadata in PNG
            "-define", "webp:metadata=none",      # strip webp metadata if present
            str(tmp_out),
        ]
    )

    # Run conversion
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    # Replace/rename atomically
    tmp_out.replace(out)

def main() -> int:
    if not IM_CMD:
        print("Error: ImageMagick not found. Install it so 'magick' or 'convert' is in PATH.", file=sys.stderr)
        return 2

    if not ROOT_DIR.exists():
        print(f"Error: directory does not exist: {ROOT_DIR}", file=sys.stderr)
        return 2

    # Walk directory
    images = [p for p in ROOT_DIR.rglob("*") if is_image_file(p)]

    images = [i for i in images if not re.search(r'_\d+percent\.', str(i))]

    if not images:
        print(f"No image files found under {ROOT_DIR}")
        return 0

    total_created = 0
    total_skipped = 0
    total_failed = 0

    for src in images:
        for percent in SCALES:
            out = output_path_for_scale(src, percent)

            if already_done(out):
                total_skipped += 1
                continue

            try:
                run_imagemagick(src, out, percent)
                total_created += 1
                print(f"Created: {out}")
            except subprocess.CalledProcessError as e:
                total_failed += 1
                err = (e.stderr or b"").decode("utf-8", errors="replace").strip()
                print(f"FAILED: {src} -> {out}\n  {err}\n", file=sys.stderr)
                # Best-effort cleanup of temp
                tmp = out.with_suffix(out.suffix + ".tmp")
                try:
                    if tmp.exists():
                        tmp.unlink()
                except OSError:
                    pass

    print("\nSummary")
    print(f"  Images found:  {len(images)}")
    print(f"  Created:       {total_created}")
    print(f"  Skipped:       {total_skipped}")
    print(f"  Failed:        {total_failed}")

    return 0 if total_failed == 0 else 1

if __name__ == "__main__":
    raise SystemExit(main())

