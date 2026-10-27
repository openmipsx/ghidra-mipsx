#!/usr/bin/env python3
# Copyright 2026 Tim Retout <tim@retout.co.uk>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unpack a Sipura/Linksys SPA firmware image.

Handles both containers described in docs/sipura-image-format.md, and images
embedded in the vendor's Windows upgrade programs. Checks every checksum and
writes, into the output directory:

  flash.bin                 the reassembled flash (flash container only)
  sec<type>_<version>.raw   each section's data
  sec<type>_<version>_<load address>.bin
                            each decompressed stream of a packed section

and prints each section's load directory.

Usage: sipura_unpack.py <image.bin|upgrader.exe> <output-dir>
"""
import hashlib
import os
import re
import struct
import sys
import zlib

HEADER_SIZE = 0x80
BLOCK = 0x10000
RECORD_NAMES = {0x02: "zero-fill", 0x03: "entry", 0x05: "r24", 0x06: "r25?",
                0x07: "r23", 0x0A: "r22", 0x10: "stream", 0x13: "r26"}


def u32(b, off):
    return struct.unpack_from(">I", b, off)[0]


def find_image(d):
    """Return the image inside d (a bare image or an upgrade program)."""
    for m in re.finditer(rb"(?i)firmware", d):
        start = m.start() - 8
        if start < 0 or start + HEADER_SIZE > len(d):
            continue
        h = d[start:start + HEADER_SIZE]
        length = u32(h, 0x58)
        if (u32(h, 0x50) == HEADER_SIZE and u32(h, 0x54) in (0x40, 0x80)
                and 1 <= u32(h, 0x7C) <= 256 and start + length <= len(d)):
            return d[start:start + length], start
    sys.exit("no Sipura firmware image found")


def check(ok, what):
    print(f"  {what}: {'ok' if ok else 'BAD'}")


def section_container(img):
    count = u32(img, 0x7C)
    off = HEADER_SIZE + count * 0x80
    for i in range(count):
        entry = img[HEADER_SIZE + i * 0x80:HEADER_SIZE + (i + 1) * 0x80]
        length = u32(entry, 0x20)
        yield entry, img[off + 0x80:off + 0x80 + length]
        off += 0x80 + length


def flash_container(img, outdir):
    count = u32(img, 0x7C)
    blocks = {}
    for i in range(count):
        e = img[HEADER_SIZE + i * 0x40:HEADER_SIZE + (i + 1) * 0x40]
        num, stored, length, off = struct.unpack_from(">HHII", e)
        raw = img[off:off + length]
        if stored:
            data = raw
        else:
            z = zlib.decompressobj(-15)
            data = z.decompress(raw)
            tail = z.unused_data
            if len(tail) >= 4 and u32(tail, 0) != zlib.adler32(data):
                print(f"  block {num:#x}: Adler-32 BAD")
        if hashlib.md5(data).digest() != e[12:28]:
            print(f"  block {num:#x}: MD5 BAD")
        blocks[num] = data
    print(f"  {len(blocks)} flash blocks, MD5s checked")
    flash = bytearray(b"\xff" * ((max(blocks) + 1) * BLOCK))
    for num, data in blocks.items():
        flash[num * BLOCK:num * BLOCK + len(data)] = data
    write(outdir, "flash.bin", flash)
    for num in sorted(blocks):
        entry = flash[num * BLOCK:num * BLOCK + 0x80]
        if u32(entry, 0) == 0 and entry[8] <= 2 and u32(entry, 0x0C) == 0x80:
            length = u32(entry, 0x20)
            start = num * BLOCK + 0x80
            print(f"  section type {entry[8]} at flash offset {num * BLOCK:#x}")
            yield bytes(entry), bytes(flash[start:start + length])


def packed(sec, name, outdir):
    dir_off, dir_count = u32(sec, 4), u32(sec, 8)
    for i in range(dir_count):
        rec = struct.unpack_from(">5I", sec, dir_off + i * 20)
        kind = RECORD_NAMES.get(rec[0], "unknown")
        if rec[0] == 0x10:
            z = zlib.decompressobj(-15)
            out = z.decompress(sec[rec[1] + 8:])
            crc, length = struct.unpack_from("<II", z.unused_data)
            ok = crc == zlib.crc32(out) and length == len(out)
            print(f"    {rec[0]:#04x} {kind:9} load {rec[2]:#010x} {len(out):#8x} bytes, "
                  f"CRC-32 {'ok' if ok else 'BAD'}")
            write(outdir, f"{name}_{rec[2]:08x}.bin", out)
        elif rec[0] == 0x02:
            print(f"    {rec[0]:#04x} {kind:9} {rec[1]:#010x} {rec[2]:#8x} bytes")
        elif rec[0] == 0x03:
            word = rec[1] & 0x3FFFFFFF
            print(f"    {rec[0]:#04x} {kind:9} byte {word * 4:#010x} (flag {rec[1] >> 30 & 1})")
        else:
            print(f"    {rec[0]:#04x} {kind:9} word {rec[1]:#x} (byte {rec[1] * 4:#x})")


def write(outdir, fname, data):
    with open(os.path.join(outdir, fname), "wb") as f:
        f.write(data)


def main(path, outdir):
    with open(path, "rb") as f:
        img, start = find_image(f.read())
    os.makedirs(outdir, exist_ok=True)
    print(f"{img[:16].decode('latin-1')} version "
          f"{img[0x5C:0x7C].split(b'\0')[0].decode()}, {len(img):#x} bytes at {start:#x}")
    count, esz = u32(img, 0x7C), u32(img, 0x54)
    hdr = bytearray(img[:HEADER_SIZE + count * esz])
    hdr[0x30:0x40] = bytes(16)
    check(hashlib.md5(hdr).digest() == img[0x30:0x40], "header MD5")
    sections = (section_container(img) if esz == 0x80
                else flash_container(img, outdir))
    for entry, data in sections:
        version = entry[0x28:0x7E].split(b"\0")[0].decode()
        name = f"sec{entry[8]}_{version}"
        print(f"{name}: {len(data):#x} bytes")
        check(hashlib.md5(data).digest() == entry[0x10:0x20], "section MD5")
        check(sum(entry[:0x7E]) & 0xFFFF == struct.unpack_from(">H", entry, 0x7E)[0],
              "entry byte sum")
        write(outdir, f"{name}.raw", data)
        if data[:4] == b"\x00\x06\x08\x03":
            packed(data, name, outdir)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
