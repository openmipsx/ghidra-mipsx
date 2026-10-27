# Sipura SPA firmware image format

Status: draft, 2026-10-27. Worked out from SPA3000 3.1.20(GW), then checked
against the eighteen images listed in the [README](../README.md). It
describes what the loader in this extension relies on. The format
description is original and contains no vendor code or text.

Each fact is marked:

- **Verified**: checked by computation against every image (checksums
  match, lengths add up, streams decompress).
- **Observed**: the value is in the images, but its meaning is unknown or
  inferred.
- **Hypothesis**: a plausible explanation that has not been confirmed.

Multi-byte integers are **big-endian** unless stated otherwise. Offsets are
in hex.

## 1. Two containers

Every image starts with the same 0x80-byte global header (§2). After it
comes one of two containers, told apart by header field 0x54:

| 0x54 | Container | Models |
|---|---|---|
| 0x80 | **Section container** (§3): three sections stored one after another | SPA1001, SPA2000, SPA3000 (2.x and 3.x) and their recovery releases |
| 0x40 | **Flash container** (§5): deflated 64 KiB flash blocks, which hold the same three sections | SPA2002, PAP2T, SPA2100, SPA2102, SPA841, SPA941, SPA9000 |

Either way the device ends up with the same sections (§4), each preceded
by a 0x80-byte entry. The vendor's Windows upgraders embed the image
unchanged (**Verified**); the recovery releases (`rec*.exe`) ship only as
upgraders.

## 2. Global header (0x000–0x07F)

| Offset | Size | Meaning | Status |
|---|---|---|---|
| 0x00 | 16 | Magic: an 8-byte model name and `FiRmWaRe`, for example `SpA3000 FiRmWaRe`, `SpA2100fFiRmWaRe`, `KoSmOsF FiRmWaRe` (SPA841), `kOsMoS9 fIrMwArE` (SPA941). The loader accepts any 8 bytes followed by "firmware" in any case | Observed |
| 0x10 | 32 | Zero | Observed |
| 0x30 | 16 | MD5 over bytes 0 to the end of the table, computed with this field set to zero | **Verified** |
| 0x40 | 16 | Zero in most images; non-zero in SPA2102 5.1.6, SPA941 4.1.15 and SPA9000 3.2.5(c), where it is included in the MD5 above | Observed |
| 0x50 | 4 | 0x80: header size | Observed |
| 0x54 | 4 | Table entry size: 0x80 or 0x40 (§1) | Observed |
| 0x58 | 4 | Total image length | **Verified** |
| 0x5C | 32 | Image version string, NUL-padded | Observed |
| 0x7C | 4 | Number of table entries | **Verified** |

## 3. Section container

The table holds `count` (3 in every image seen) entries of 0x80 bytes from
0x080. The sections follow at 0x080 + count × 0x80, each as a byte-for-byte
copy of its table entry followed by its data. The last section ends exactly
at the image length (**Verified**).

## 4. Sections

### 4.1 Section entry (0x80 bytes)

| Offset | Size | Meaning | Status |
|---|---|---|---|
| 0x00 | 4 | Zero | Observed |
| 0x04 | 4 | Tag, the same for each section type in every image: 0xCACAD3C3 (type 2), 0xB8B4D4AD (type 1), 0xC6F4B6AF (type 0) | Observed |
| 0x08 | 1 | Section type: 2, 1 or 0 | Observed |
| 0x0C | 4 | 0x80: entry size | Observed |
| 0x10 | 16 | MD5 of the section data | **Verified** |
| 0x20 | 4 | Section data length | **Verified** |
| 0x28 | 0x56 | Section version string, NUL-padded | Observed |
| 0x7E | 2 | Sum of entry bytes 0x00–0x7D as unsigned bytes, mod 0x10000 | **Verified** |

| Type | Encoding | Role |
|---|---|---|
| 2 | Packed (§4.2) | Main application |
| 1 | Packed (§4.2) | A second, smaller program (Hypothesis: recovery or helper image) |
| 0 | Raw, 0xDF80 bytes in every image | Unknown. It does not decode as MIPS-X; perhaps the second core's code, or data. Load address unknown |

### 4.2 Packed section

Offsets are relative to the start of the section data.

| Offset | Size | Meaning | Status |
|---|---|---|---|
| 0x00 | 4 | 0x00060803 | Observed |
| 0x04 | 4 | Offset of the load directory | **Verified** |
| 0x08 | 4 | Number of load directory records | **Verified** |
| 0x0C | 4 | Hypothesis: initial stack pointer | Hypothesis |
| 0x10 | 4 | Section data length | **Verified** |
| 0x14 | 4 | Section data length − 0x10 | Observed |

From 0x20 there may be auxiliary chunks, each `01 <type> 00 00 <u32
length> <data>`; the list ends at the first byte that is not 0x01. In the
application section they hold the voice prompts and their index
(Hypothesis). They are not part of the memory image.

After them come compressed stream records, found through the load
directory. Each is 8 bytes of unknown meaning, then a raw deflate stream
(RFC 1951), then the CRC-32 and the length of the uncompressed data, both
**little-endian** (the gzip trailer). **Verified** for every stream.

The section ends with a short trailing area that looks like a loader stub.

### 4.3 Load directory

`count` records of 20 bytes (5 × u32). Word 0 is the record type.

| Type | Word 1 | Word 2 | Meaning | Status |
|---|---|---|---|---|
| 0x10 | Offset of the stream record | Load address (bytes) | Decompress the stream to the load address | **Verified** |
| 0x02 | Address | Length | Zero-fill (BSS) | Hypothesis, strongly supported |
| 0x03 | Bits 29–0: entry point as a **word** address; bit 30: a flag of unknown meaning | | Entry point | Observed. Absent from the application section of SPA2002, PAP2T, SPA841 and SPA941 |
| 0x07, 0x05, 0x0A, 0x13 | A word address | | Initial value of code base register r23, r24, r22 or r26 | **Verified**; see [`processor-es3890.md`](processor-es3890.md) §8 |
| 0x06 | 0x10000 or 0x20000 | | Probably the initial value of r25 | Hypothesis |

Other words in non-stream records vary irregularly and look like leftover
buffer contents (Observed).

## 5. Flash container

The table holds `count` entries of 0x40 bytes from 0x080, one per flash
block:

| Offset | Size | Meaning | Status |
|---|---|---|---|
| 0x00 | 2 | Flash block number; the block's flash offset is number × 0x10000 | Observed (sections land at block starts) |
| 0x02 | 2 | 0: deflated; 1: stored | **Verified** |
| 0x04 | 4 | Stored length in the image | **Verified** |
| 0x08 | 4 | Offset of the stored data in the image | **Verified** |
| 0x0C | 16 | MD5 of the block's uncompressed contents | **Verified** |
| 0x1C | 36 | Zero | Observed |

A deflated block is a raw deflate stream followed by the big-endian
Adler-32 of the uncompressed data (**Verified**), which is to say a zlib
stream without its 2-byte header. Uncompressed blocks are at most 0x10000
bytes; a shorter one leaves the rest of the flash block erased.

The sections of §4 start at the beginning of a block, as a 0x80-byte entry
followed by the data, and run on into the following blocks. The loader
finds them by looking for a valid entry at each block start.

Some flash blocks are not part of any section. In SPA2002, PAP2T, SPA841
and SPA941, blocks 0x10–0x17 hold about 1,500 functions of uncompressed MIPS-X
code (Observed). Its load address is not known, and the application's r24
value (0x03010060) probably points into it. The loader does not load it.

## 6. Open questions

| Question | Why it matters |
|---|---|
| The 8 bytes before each deflate stream, and word 3 of stream records | Writing images |
| Bit 30 of the entry record | Boot behaviour |
| Load address and role of the type 0 section | Boot chain |
| Load address of the uncompressed flash code in SPA2002, PAP2T, SPA841 and SPA941 | Analysing those images fully |
| Is type 0x06 really r25? | Calling convention |
