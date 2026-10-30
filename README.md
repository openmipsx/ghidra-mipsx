# ghidra-mipsx

A Ghidra extension for firmware that runs on **MIPS-X**, the Stanford RISC
design that ESS Technology used in its ES38xx chips. It contains:

- a SLEIGH **processor module** for MIPS-X as implemented in the ESS
  ES3890 (language `MIPS-X:BE:32:ES3890`), and
- a **loader** for the firmware images of the Sipura and Linksys SPA
  analogue telephone adapters and IP phones, which run on that chip.

MIPS-X is not the commercial MIPS architecture, and no mainstream compiler
or disassembler supports it. This extension was written from the public
instruction set manual (Paul Chow, *MIPS-X Instruction Set and
Programmer's Manual*, Stanford CSL-86-289,
[PDF](https://www.eecg.utoronto.ca/~pc/research/publications/mipsx.isetman.pdf))
and from analysis of the firmware, and contains no vendor code.

## Generic MIPS-X or Sipura-specific?

Both, in layers:

| Part | Scope |
|---|---|
| Instruction decoding and semantics | MIPS-X as ESS built it. The ES3890 differs from the Stanford manual: it uses the coprocessor and floating-point memory opcodes as byte and halfword loads and stores, and later firmware uses an AND-immediate and a variable shift the manual does not have. Other ESS chips (the ES3207, ES3210 and ES388x video CD and DVD decoders) also use MIPS-X cores and may well decode correctly, but this has not been tested |
| Code base registers | The SPA firmware's compiler calls functions through registers holding a fixed code address (r22, r23, r24, r26). The language has context fields `base22`, `base23`, `base24` and `base26` for them; at 0 (the default) such calls decode as computed calls, so other firmware is unaffected. Set them in Ghidra's register manager if your firmware uses the same convention |
| Calling convention | Inferred from the SPA firmware (r29 stack, r31 return address, arguments in r4 upwards, result in r2). Partly guesswork; see [`docs/processor-es3890.md`](docs/processor-es3890.md) §7 |
| Loader | Sipura/Linksys SPA firmware images only |
| Scripts | `MipsXFindFunctions` relies on the SPA compiler's return sequence, which is probably common to ESS's toolchain |

## Tested firmware

Each image's application (section 2) and second program (section 1) was
imported, analysed, given a `MipsXFindFunctions` pass and analysed again
(see [Testing](#testing)). *Code* is the share of executable memory that
ends up disassembled; the rest is mostly data in the code streams.
*Errors* counts Ghidra's error bookmarks.

| Image | Container | Application functions | Code | Errors | Second program functions |
|---|---|---:|---:|---:|---:|
| SPA1001 2.0.13(SEg) | sections | 2,964 | 76.9% | 9 | 654 |
| SPA1001 3.1.8(SEc) | sections | 2,986 | 77.1% | 9 | 654 |
| SPA1001 recovery 3.1.3(SE) `.exe` | sections | 2,965 | 77.2% | 5 | 654 |
| SPA2000 2.0.13(g) | sections | 2,957 | 76.2% | 6 | 654 |
| SPA2000 3.1.5 | sections | 2,972 | 76.4% | 3 | 654 |
| SPA2000 recovery 2.0.10(e) `.exe` | sections | 2,896 | 76.0% | 7 | 654 |
| SPA3000 2.0.13(GWg) | sections | 3,022 | 76.0% | 3 | 654 |
| SPA3000 3.1.10(GWd) | sections | 3,091 | 74.8% | 3 | 724 |
| SPA3000 3.1.20(GW) | sections | 3,117 | 75.6% | 3 | 724 |
| SPA3000 recovery 2.0.11(GWa) `.exe` | sections | 3,013 | 76.3% | 6 | 654 |
| SPA2002 3.1.5 | flash | 1,535 | 70.4% | 1 | 835 |
| PAP2T 5.1.1(LS) | flash | 1,614 | 69.1% | 2 | 849 |
| PAP2T 5.1.6(LS) (also its `.exe`) | flash | 1,622 | 70.8% | 1 | 849 |
| SPA841 3.1.4(a) | flash | 1,774 | 68.1% | 4 | 990 |
| SPA941 4.1.15 | flash | 1,976 | 69.2% | 1 | 997 |
| SPA942 4.1.12(a) | flash | 3,817 | 75.0% | 15 | 1,062 |
| SPA942 4.1.15 | flash | 3,871 | 75.3% | 25 | 1,062 |
| SPA2100 3.3.6 | flash | 4,926 | 76.0% | 23 | 973 |
| SPA2102 5.1.6 | flash | 5,085 | 75.0% | 22 | 986 |
| SPA9000 3.2.5(c) | flash | 5,227 | 71.6% | 33 | 976 |

All checksums (header MD5, section MD5 and byte sum, block MD5 and
Adler-32, stream CRC-32) verify in every image. No firmware is included in
this repository; the images are the vendors' copyright.

## Limitations

- **SPA2002, PAP2T, SPA841, SPA941:** these keep about 1,500 more functions as
  uncompressed code in flash, outside every section. Its load address is
  not known, so the loader does not load it, and the application's calls
  through r24 (which probably point into it) stay unresolved. Their
  application sections also have no entry point record; run
  `MipsXFindFunctions` to find the code.
- **Section 0** (raw, 0xDF80 bytes in every image) is MIPS-X, not opaque
  data. It holds two code regions: a block that decodes at load address 0
  (byte-identical across devices, probably boot or loader code) and an
  embedded image prefixed by a `0x00060803` header, whose size is the
  header's second word and whose entry is 0x20 past the header. The loader
  maps the section at 0; run `MipsXFindFunctions` to find the first
  region's code, and carve the embedded image out to load it at its own
  base. The embedded image's calls go through r23 only; set `base23` =
  `0x10008` (the same constant in every image seen, and its entry dispatches
  through r23) to resolve all of its functions.
- The calling convention is partly guessed, so decompiler output for
  arguments and return values may be wrong.
- The extension is built for **Ghidra 12.2**. Ghidra extensions are tied to
  the version they were built against; rebuild for others (untested).

The details are in [`docs/sipura-image-format.md`](docs/sipura-image-format.md)
and [`docs/processor-es3890.md`](docs/processor-es3890.md).

## Building

Requires Ghidra 12.2 and JDK 25. Use the
Gradle wrapper that ships with Ghidra, which downloads a suitable Gradle on
first use:

```
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.2_PUBLIC /path/to/ghidra_12.2_PUBLIC/support/gradle/gradlew
```

The extension zip appears in `dist/`. To check only the SLEIGH spec:

```
/path/to/ghidra_12.2_PUBLIC/support/sleigh -a data/languages
```

## Installing

In Ghidra, File > Install Extensions, add the zip from `dist/`, and
restart. Or unzip it into
`~/.config/ghidra/ghidra_12.2_PUBLIC/Extensions/`.

## Using

1. Import a firmware image: the `.bin` file, or the vendor's Windows
   upgrade program (`.exe`), which embeds it. Ghidra offers the "Sipura
   SPA firmware image" loader. Its "Section type" option chooses the
   section: 2 = application (default), 1 = second program, 0 = raw.
2. Let auto-analysis run. It follows calls from the entry point.
3. Run `MipsXFindFunctions` (Script Manager, category MIPS-X). It creates a
   function after every return instruction, which finds the code that is
   only reached through function pointers. Then run auto-analysis again.
   On SPA3000 3.1.20(GW) this takes the function count from about 660 to
   3,117.

Headless:

```
analyzeHeadless /tmp/proj spa -import spa3000-3-1-20GW.bin \
    -loader SipuraLoader -loader-sectionType 2 \
    -postScript MipsXFindFunctions.java -postScript Reanalyze.java
```

`DecompileToC.java <directory>` writes the whole program's decompilation
to one file. `MipsXReport.java` prints the summary used in the table
above.

`tools/sipura_unpack.py` unpacks an image without Ghidra: it checks every
checksum, prints the load directory, and writes each section, each
decompressed stream and (for the flash container) the reassembled flash.

## Testing

```
GHIDRA_INSTALL_DIR=/path/to/ghidra test/run-corpus.sh -s "2 1" firmware/*.bin firmware/*.exe
```

imports each image into a throwaway project with the installed extension
and prints one line per image and section, with any loader warnings.

```
GHIDRA_INSTALL_DIR=/path/to/ghidra test/run-encodings.sh
```

decodes a few words written from the processor spec with the newest zip
in `dist/` (installed into a throwaway settings directory, not your own)
and checks the results. It needs no firmware.

## Licence

Copyright 2026 Tim Retout <tim@retout.co.uk>

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
