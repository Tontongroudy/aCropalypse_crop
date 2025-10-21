#!/usr/bin/env python3

import sys
from pathlib import Path
from io import BytesIO
from PIL import Image

def read_file_bytes(path: Path):
    return path.read_bytes()

def image_bytes_from_imageobj(img: Image.Image):
    b = BytesIO()
    img.save(b, format='PNG')
    return b.getvalue()

def convert_image_to_rgb_bytes_from_path(path: Path):
    """Load image from path, convert to RGB, return PNG bytes (in-memory)."""
    im = Image.open(path).convert('RGB')
    return image_bytes_from_imageobj(im)

def convert_imageobj_to_rgb_bytes(im: Image.Image):
    """Convert PIL image object to RGB and return PNG bytes."""
    im2 = im.convert('RGB')
    return image_bytes_from_imageobj(im2)

def crop_imageobj_to_png_bytes(im: Image.Image, box: tuple, force_rgb: bool):
    """Crop PIL image object, optionally convert to RGB, and return PNG bytes."""
    left, top, right, bottom = box
    crop = im.crop((left, top, right, bottom))
    if force_rgb:
        crop = crop.convert('RGB')
    return image_bytes_from_imageobj(crop)

def find_image_mode(path: Path):
    im = Image.open(path)
    return im.mode

def make_vuln_by_mode(mode: str, input_path: str, output_path: str, box: tuple):
    ip = Path(input_path)
    if not ip.exists():
        print(f"Error: input file not found: {input_path}")
        sys.exit(1)

    op = Path(output_path)

    # Read original bytes (will be used depending on mode)
    orig_bytes = read_file_bytes(ip)

    # Inspect original mode
    im_orig = Image.open(ip)
    orig_mode = im_orig.mode
    print(f"[i] Original: mode={orig_mode}, size={im_orig.size}")

    left, top, right, bottom = box

    if mode.lower() == 'windows':
        # windows: preserve alpha if present
        if 'A' in im_orig.getbands():
            print("[i] Mode windows: original has alpha -> crop in RGBA and append original bytes (RGBA trailer).")
            # crop preserving original mode (RGBA)
            cropped = im_orig.crop((left, top, right, bottom))
            # ensure saved crop keeps RGBA (don't force convert)
            cropped_bytes = image_bytes_from_imageobj(cropped)
            trailer_bytes = orig_bytes  # append original unchanged
        else:
            print("[i] Mode windows: original has no alpha -> crop in RGB and append original bytes.")
            cropped = im_orig.crop((left, top, right, bottom)).convert('RGB')
            cropped_bytes = image_bytes_from_imageobj(cropped)
            trailer_bytes = orig_bytes

    elif mode.lower() == 'pixel':
        # pixel: ensure everything is RGB
        if 'A' in im_orig.getbands():
            print("[i] Mode pixel: original has alpha -> convert original to RGB (in-memory) and use that for trailer & crop.")
            # build in-memory RGB-converted original bytes to append => ensures trailer is RGB
            rgb_orig_bytes = convert_image_to_rgb_bytes_from_path(ip)
            # open RGB image object to crop (create from in-memory bytes to avoid reloading file)
            im_rgb = Image.open(BytesIO(rgb_orig_bytes))
            # crop in RGB
            cropped_bytes = crop_imageobj_to_png_bytes(im_rgb, box, force_rgb=True)
            trailer_bytes = rgb_orig_bytes
        else:
            print("[i] Mode pixel: original has no alpha -> crop in RGB and append original bytes.")
            # no alpha, crop in RGB and append original bytes (already RGB)
            cropped = im_orig.crop((left, top, right, bottom)).convert('RGB')
            cropped_bytes = image_bytes_from_imageobj(cropped)
            trailer_bytes = orig_bytes
    else:
        print("Error: mode must be 'windows' or 'pixel'")
        sys.exit(1)

    # Write final vulnerable file: cropped PNG bytes then trailer bytes (simulate overwrite without truncate)
    with open(op, 'wb') as out:
        out.write(cropped_bytes)
        out.write(trailer_bytes)

    print(f"[+] Wrote vulnerable file: {output_path}")
    # For debug: report whether trailer contains possible zlib header near start
    try:
        # find IEND end to show trailer head (lightweight)
        data = op.read_bytes()
        sig = b'\x89PNG\r\n\x1a\n'
        off = len(sig)
        iend_end = None
        import struct
        while off + 8 <= len(data):
            clen = struct.unpack('>I', data[off:off+4])[0]
            ctype = data[off+4:off+8]
            data_start = off + 8
            data_end = data_start + clen
            crc_end = data_end + 4
            if ctype == b'IEND':
                iend_end = crc_end
                break
            off = crc_end
        if iend_end is not None and iend_end < len(data):
            trailer_head = data[iend_end:iend_end+64]
            print("[i] Trailer head (hex, up to 64 bytes):", trailer_head.hex()[:256])
            # quick zlib header check
            if len(trailer_head) >= 2 and trailer_head[0] == 0x78 and trailer_head[1] in (0x01,0x5e,0x9c,0xda):
                print("[i] zlib-like header detected at start of trailer (good).")
            else:
                print("[i] No obvious zlib header at the very start of the trailer (may still be later).")
        else:
            print("[i] No trailer found or trailer empty.")
    except Exception as e:
        print("[!] Warning: couldn't inspect trailer:", e)

def usage_and_exit():
    print("Usage: python3 make_acropalypse_by_mode.py <windows|pixel> input.png output_vuln.png left top right bottom")
    sys.exit(1)

def parse_box(argv):
    try:
        left = int(argv[0]); top = int(argv[1]); right = int(argv[2]); bottom = int(argv[3])
        return (left, top, right, bottom)
    except Exception as e:
        raise

if __name__ == '__main__':
    if len(sys.argv) != 8:
        usage_and_exit()
    mode = sys.argv[1]
    input_path = sys.argv[2]
    output_path = sys.argv[3]
    try:
        box = parse_box(sys.argv[4:8])
    except Exception as e:
        print("Error parsing coords:", e)
        usage_and_exit()

    make_vuln_by_mode(mode, input_path, output_path, box)
