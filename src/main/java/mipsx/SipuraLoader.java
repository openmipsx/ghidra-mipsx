/* ###
 * Copyright 2026 Tim Retout <tim@retout.co.uk>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package mipsx;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.zip.Adler32;
import java.util.zip.CRC32;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for Sipura and Linksys SPA firmware upgrade images: the {@code SpA3000 FiRmWaRe},
 * {@code SpA2102 FiRmWaRe}, {@code kOsMoS9 fIrMwArE} and similar families. See
 * docs/sipura-image-format.md.
 * <p>
 * Two containers are handled: the section container (three sections stored one after another)
 * and the flash container (deflated 64 KiB flash blocks that hold the same sections). The image
 * may also be embedded in a Windows upgrade program, as the vendor's recovery releases are.
 * <p>
 * One section is loaded per import, chosen by the "Section type" option: 2 (application,
 * default), 1 (second packed program) or 0 (raw, load address unknown).
 */
public class SipuraLoader extends AbstractProgramWrapperLoader {

	public static final String LOADER_NAME = "Sipura SPA firmware image";
	public static final String OPTION_SECTION_TYPE = "Section type";

	static final LanguageCompilerSpecPair LANGUAGE =
		new LanguageCompilerSpecPair("MIPS-X:BE:32:ES3890", "default");

	private static final int HEADER_SIZE = 0x80;
	private static final int SECTION_ENTRY_SIZE = 0x80;
	private static final int FLASH_ENTRY_SIZE = 0x40;
	private static final int FLASH_BLOCK_SIZE = 0x10000;
	private static final int PACKED_HEADER_SIZE = 0x20;
	private static final int DIR_RECORD_SIZE = 20;
	private static final byte[] PACKED_MAGIC = { 0x00, 0x06, 0x08, 0x03 };

	// Load directory record types
	private static final int REC_STREAM = 0x10;
	private static final int REC_ZERO_FILL = 0x02;
	private static final int REC_ENTRY = 0x03;
	private static final int REC_R24 = 0x05;
	private static final int REC_R25 = 0x06;
	private static final int REC_R23 = 0x07;
	private static final int REC_R22 = 0x0A;
	private static final int REC_R26 = 0x13;

	/** One section: its table entry (0x80 bytes) and data. */
	record Section(int index, int type, String version, byte[] entry, byte[] data) {
	}

	@Override
	public String getName() {
		return LOADER_NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 0;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		if (findImage(provider) >= 0) {
			loadSpecs.add(new LoadSpec(this, 0, LANGUAGE, true));
		}
		return loadSpecs;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = new ArrayList<>();
		list.add(Option.newInteger(OPTION_SECTION_TYPE)
				.value(2)
				.commandLineArgument(createArg("-sectionType"))
				.description("Section to load: 2 = application, 1 = second packed program, " +
					"0 = raw section (load address unknown, loaded at 0)")
				.build());
		list.addAll(super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram,
			mirrorFsLayout));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		for (Option option : options) {
			if (option.getName().equals(OPTION_SECTION_TYPE)) {
				if (!Integer.class.isAssignableFrom(option.getValueClass())) {
					return "Invalid type for option: " + OPTION_SECTION_TYPE;
				}
				int type = (Integer) option.getValue();
				if (type < 0 || type > 2) {
					return OPTION_SECTION_TYPE + " must be 0, 1 or 2";
				}
			}
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		ByteProvider provider = settings.provider();

		long start = findImage(provider);
		if (start < 0) {
			throw new IOException("No Sipura firmware image found");
		}
		int length = (int) u32(provider.readBytes(start + 0x58, 4), 0);
		byte[] image = provider.readBytes(start, length);
		log.appendMsg(String.format("Image %s, version %s, %#x bytes at file offset %#x",
			cString(image, 0, 16), cString(image, 0x5C, 0x20), length, start));
		checkGlobalMd5(image, log);

		List<Section> sections = entrySize(image) == SECTION_ENTRY_SIZE
				? parseSectionContainer(image, log)
				: parseFlashContainer(image, log, monitor);
		for (Section s : sections) {
			checkSection(s, log);
		}

		int wanted = OptionUtils.getOption(OPTION_SECTION_TYPE, settings.options(), 2);
		Section section = sections.stream().filter(s -> s.type() == wanted).findFirst()
				.orElseThrow(() -> new IOException("No section of type " + wanted + " in image"));
		log.appendMsg(String.format("Loading section %d: type %d, version %s, %#x bytes",
			section.index(), section.type(), section.version(), section.data().length));

		if (section.type() == 0) {
			loadRaw(program, section.data(), log, monitor);
		}
		else {
			loadPacked(program, section.data(), log, monitor);
		}
	}

	// ---- finding the image ----

	/**
	 * Return the offset of a firmware image in the file: 0 for a bare image, or the offset of an
	 * image embedded in a Windows upgrade program. -1 if there is none.
	 */
	static long findImage(ByteProvider provider) throws IOException {
		long size = provider.length();
		if (size < 0x200) {
			return -1;
		}
		if (isHeader(provider.readBytes(0, HEADER_SIZE), size)) {
			return 0;
		}
		byte[] mz = provider.readBytes(0, 2);
		if (mz[0] != 'M' || mz[1] != 'Z' || size > 64 * 1024 * 1024) {
			return -1;
		}
		byte[] file = provider.readBytes(0, size);
		for (int i = 8; i + HEADER_SIZE - 8 <= file.length; i++) {
			if ((file[i] | 0x20) == 'f' && regionMatchesIgnoreCase(file, i, "firmware") &&
				isHeader(Arrays.copyOfRange(file, i - 8, i - 8 + HEADER_SIZE), size - (i - 8))) {
				return i - 8;
			}
		}
		return -1;
	}

	/**
	 * A plausible image header: an 8-byte model name followed by "firmware" in mixed case, the
	 * header and entry sizes, and a total length that fits in what is left of the file.
	 */
	private static boolean isHeader(byte[] h, long available) {
		if (!regionMatchesIgnoreCase(h, 8, "firmware")) {
			return false;
		}
		long esz = u32(h, 0x54);
		long len = u32(h, 0x58);
		long count = u32(h, 0x7C);
		return u32(h, 0x50) == HEADER_SIZE && (esz == SECTION_ENTRY_SIZE ||
			esz == FLASH_ENTRY_SIZE) && count >= 1 && count <= 256 &&
			len >= HEADER_SIZE + count * esz && len <= available;
	}

	private static boolean regionMatchesIgnoreCase(byte[] b, int off, String s) {
		if (off + s.length() > b.length) {
			return false;
		}
		return new String(b, off, s.length(), StandardCharsets.ISO_8859_1)
				.equalsIgnoreCase(s);
	}

	private static int entrySize(byte[] image) {
		return (int) u32(image, 0x54);
	}

	// ---- containers ----

	/** Section container: the table entries, then each section as an entry copy and data. */
	private List<Section> parseSectionContainer(byte[] image, MessageLog log) throws IOException {
		int count = (int) u32(image, 0x7C);
		List<Section> sections = new ArrayList<>();
		int off = HEADER_SIZE + count * SECTION_ENTRY_SIZE;
		for (int i = 0; i < count; i++) {
			int e = HEADER_SIZE + i * SECTION_ENTRY_SIZE;
			byte[] entry = Arrays.copyOfRange(image, e, e + SECTION_ENTRY_SIZE);
			int length = (int) u32(entry, 0x20);
			int dataOffset = off + SECTION_ENTRY_SIZE;
			if (length < 0 || dataOffset + (long) length > image.length) {
				throw new IOException(String.format("Section %d (%#x bytes at %#x) runs past " +
					"end of image", i, length, dataOffset));
			}
			if (!Arrays.equals(image, e, e + SECTION_ENTRY_SIZE, image, off, dataOffset)) {
				warn(log, String.format("Section %d entry copy at %#x differs from table entry",
					i, off));
			}
			sections.add(new Section(i, entry[8] & 0xFF, cString(entry, 0x28, 0x56), entry,
				Arrays.copyOfRange(image, dataOffset, dataOffset + length)));
			off = dataOffset + length;
		}
		if (off != image.length) {
			warn(log, String.format("Sections end at %#x, image is %#x bytes", off,
				image.length));
		}
		return sections;
	}

	/**
	 * Flash container: each table entry is one 64 KiB flash block, stored or deflated. The
	 * sections are found at the start of blocks and may run on into the following blocks.
	 */
	private List<Section> parseFlashContainer(byte[] image, MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		int count = (int) u32(image, 0x7C);
		TreeMap<Integer, byte[]> blocks = new TreeMap<>();
		for (int i = 0; i < count; i++) {
			monitor.checkCancelled();
			int e = HEADER_SIZE + i * FLASH_ENTRY_SIZE;
			int block = u16(image, e);
			boolean stored = u16(image, e + 2) != 0;
			int length = (int) u32(image, e + 4);
			int offset = (int) u32(image, e + 8);
			if (length < 0 || offset < 0 || offset + (long) length > image.length) {
				throw new IOException(String.format("Flash block %#x (%#x bytes at %#x) runs " +
					"past end of image", block, length, offset));
			}
			byte[] data = stored ? Arrays.copyOfRange(image, offset, offset + length)
					: inflateBlock(image, offset, length, block, log);
			if (data == null) {
				continue;
			}
			if (data.length > FLASH_BLOCK_SIZE) {
				warn(log, String.format("Flash block %#x is %#x bytes, more than a block",
					block, data.length));
			}
			if (!Arrays.equals(md5(data), Arrays.copyOfRange(image, e + 12, e + 28))) {
				warn(log, String.format("Flash block %#x MD5 does not match", block));
			}
			blocks.put(block, data);
		}
		log.appendMsg(String.format("Flash container: %d blocks, %#x-%#x", blocks.size(),
			blocks.firstKey() * FLASH_BLOCK_SIZE, (blocks.lastKey() + 1) * FLASH_BLOCK_SIZE - 1));

		List<Section> sections = new ArrayList<>();
		for (Map.Entry<Integer, byte[]> b : blocks.entrySet()) {
			byte[] first = b.getValue();
			if (first.length < SECTION_ENTRY_SIZE || u32(first, 0) != 0 || first[8] < 0 ||
				first[8] > 2 || u32(first, 0x0C) != SECTION_ENTRY_SIZE) {
				continue;
			}
			int length = (int) u32(first, 0x20);
			ByteArrayOutputStream run = new ByteArrayOutputStream();
			for (int k = b.getKey(); run.size() < SECTION_ENTRY_SIZE + length; k++) {
				byte[] data = blocks.get(k);
				if (data == null) {
					break;
				}
				run.write(data, 0, data.length);
				// Blocks are erased to 0xFF beyond the stored data.
				byte[] pad = new byte[FLASH_BLOCK_SIZE - Math.min(data.length, FLASH_BLOCK_SIZE)];
				Arrays.fill(pad, (byte) 0xFF);
				run.write(pad, 0, pad.length);
			}
			byte[] bytes = run.toByteArray();
			if (bytes.length < SECTION_ENTRY_SIZE + length) {
				warn(log, String.format("Section at flash block %#x runs past the last block",
					b.getKey()));
				continue;
			}
			byte[] entry = Arrays.copyOfRange(bytes, 0, SECTION_ENTRY_SIZE);
			log.appendMsg(String.format("Section type %d at flash offset %#x", entry[8],
				b.getKey() * FLASH_BLOCK_SIZE));
			sections.add(new Section(sections.size(), entry[8], cString(entry, 0x28, 0x56),
				entry, Arrays.copyOfRange(bytes, SECTION_ENTRY_SIZE, SECTION_ENTRY_SIZE + length)));
		}
		return sections;
	}

	/** Inflate one flash block: raw deflate followed by a big-endian Adler-32. */
	private byte[] inflateBlock(byte[] image, int offset, int length, int block,
			MessageLog log) {
		Inflater inflater = new Inflater(true);
		try {
			inflater.setInput(image, offset, length);
			byte[] out = new byte[FLASH_BLOCK_SIZE];
			int n = 0;
			while (!inflater.finished() && n < out.length) {
				int k = inflater.inflate(out, n, out.length - n);
				if (k == 0 && (inflater.needsInput() || inflater.needsDictionary())) {
					warn(log, String.format("Flash block %#x is truncated", block));
					return null;
				}
				n += k;
			}
			if (!inflater.finished()) {
				warn(log, String.format("Flash block %#x inflates to more than a block", block));
			}
			byte[] data = Arrays.copyOf(out, n);
			int end = offset + length - inflater.getRemaining();
			if (end + 4 <= offset + length) {
				Adler32 adler = new Adler32();
				adler.update(data);
				if (adler.getValue() != u32(image, end)) {
					warn(log, String.format("Flash block %#x Adler-32 does not match", block));
				}
			}
			return data;
		}
		catch (DataFormatException e) {
			warn(log, String.format("Flash block %#x does not inflate: %s", block,
				e.getMessage()));
			return null;
		}
		finally {
			inflater.end();
		}
	}

	// ---- checks ----

	/** MD5 over the header and table, with the digest field set to zero. */
	private void checkGlobalMd5(byte[] image, MessageLog log) {
		int tableEnd = HEADER_SIZE + (int) u32(image, 0x7C) * entrySize(image);
		byte[] hdr = Arrays.copyOfRange(image, 0, tableEnd);
		Arrays.fill(hdr, 0x30, 0x40, (byte) 0);
		if (!Arrays.equals(md5(hdr), Arrays.copyOfRange(image, 0x30, 0x40))) {
			warn(log, String.format("Header MD5 (0x000-%#x) does not match", tableEnd - 1));
		}
	}

	private void checkSection(Section s, MessageLog log) {
		if (entrySum(s.entry()) != u16(s.entry(), 0x7E)) {
			warn(log, String.format("Section %d entry byte sum does not match", s.index()));
		}
		if (!Arrays.equals(md5(s.data()), Arrays.copyOfRange(s.entry(), 0x10, 0x20))) {
			warn(log, String.format("Section %d data MD5 does not match", s.index()));
		}
	}

	private static int entrySum(byte[] entry) {
		int sum = 0;
		for (int i = 0; i < 0x7E; i++) {
			sum += entry[i] & 0xFF;
		}
		return sum & 0xFFFF;
	}

	// ---- loading ----

	private void loadRaw(Program program, byte[] data, MessageLog log, TaskMonitor monitor)
			throws IOException {
		warn(log, "The raw type 0 section's load address is unknown; loaded at 0");
		createBlock(program, "raw_00000000", 0, data, "Raw type 0 section, load address unknown",
			true, log, monitor);
	}

	private void loadPacked(Program program, byte[] sec, MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (sec.length < PACKED_HEADER_SIZE || !Arrays.equals(sec, 0, 4, PACKED_MAGIC, 0, 4)) {
			throw new IOException("Not a packed section");
		}
		int dirOffset = (int) u32(sec, 0x04);
		int dirCount = (int) u32(sec, 0x08);
		if (dirCount < 0 || dirOffset < PACKED_HEADER_SIZE ||
			dirOffset + (long) dirCount * DIR_RECORD_SIZE > sec.length) {
			throw new IOException(String.format("Bad load directory: %d records at %#x",
				dirCount, dirOffset));
		}
		log.appendMsg(String.format("Header word 0x0C (stack top?): %#x", u32(sec, 0x0C)));

		// Auxiliary chunks (voice prompts etc.) are not part of the memory image; skip them.
		int off = PACKED_HEADER_SIZE;
		while (off + 8 <= sec.length && sec[off] == 1) {
			long len = u32(sec, off + 4);
			log.appendMsg(String.format("Skipping auxiliary chunk type %d, %#x bytes at %#x",
				sec[off + 1] & 0xFF, len, off));
			off += 8 + (int) len;
		}

		List<long[]> records = new ArrayList<>();
		for (int i = 0; i < dirCount; i++) {
			int r = dirOffset + i * DIR_RECORD_SIZE;
			records.add(new long[] { u32(sec, r), u32(sec, r + 4), u32(sec, r + 8),
				u32(sec, r + 12), u32(sec, r + 16) });
		}

		// Memory first, so that the register values below cover every block.
		for (long[] rec : records) {
			monitor.checkCancelled();
			if (rec[0] == REC_STREAM) {
				byte[] out = inflateRecord(sec, (int) rec[1], log);
				if (out != null) {
					createBlock(program, String.format("load_%08x", rec[2]), rec[2], out,
						String.format("Stream at section offset %#x", rec[1]), true, log, monitor);
				}
			}
			else if (rec[0] == REC_ZERO_FILL) {
				createBlock(program, String.format("bss_%08x", rec[1]), rec[1],
					new byte[(int) rec[2]], "Zero-fill (load directory type 0x02)", false, log,
					monitor);
			}
		}

		boolean entry = false;
		for (long[] rec : records) {
			switch ((int) rec[0]) {
				case REC_STREAM, REC_ZERO_FILL -> {
				}
				case REC_R22 -> setRegisters(program, rec[1], "base22", "r22", log);
				case REC_R23 -> setRegisters(program, rec[1], "base23", "r23", log);
				case REC_R24 -> setRegisters(program, rec[1], "base24", "r24", log);
				case REC_R25 -> setRegisters(program, rec[1], null, "r25", log);
				case REC_R26 -> setRegisters(program, rec[1], "base26", "r26", log);
				case REC_ENTRY -> {
					setEntry(program, rec[1], log);
					entry = true;
				}
				default -> warn(log, String.format("Unknown load directory record type %#x " +
					"(value %#x)", rec[0], rec[1]));
			}
		}
		if (!entry) {
			warn(log, "No entry point in the load directory; run MipsXFindFunctions to find code");
		}
	}

	/** Inflate the stream record at the given section offset; null if it is unusable. */
	private byte[] inflateRecord(byte[] sec, int recOffset, MessageLog log) {
		int start = recOffset + 8; // 8-byte prefix of unknown meaning
		if (recOffset < 0 || start >= sec.length) {
			warn(log, String.format("Stream record offset %#x out of range", recOffset));
			return null;
		}
		Inflater inflater = new Inflater(true);
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			inflater.setInput(sec, start, sec.length - start);
			byte[] buf = new byte[0x10000];
			while (!inflater.finished()) {
				int n = inflater.inflate(buf);
				if (n == 0 && (inflater.needsInput() || inflater.needsDictionary())) {
					warn(log, String.format("Stream at %#x is truncated", recOffset));
					return null;
				}
				out.write(buf, 0, n);
			}
			int end = sec.length - inflater.getRemaining();
			byte[] data = out.toByteArray();
			if (end + 8 > sec.length) {
				warn(log, String.format("Stream at %#x has no trailer", recOffset));
				return data;
			}
			CRC32 crc = new CRC32();
			crc.update(data);
			long wantCrc = u32le(sec, end);
			long wantLen = u32le(sec, end + 4);
			if (crc.getValue() != wantCrc) {
				warn(log, String.format("Stream at %#x: CRC-32 %08x, trailer says %08x",
					recOffset, crc.getValue(), wantCrc));
			}
			if (data.length != wantLen) {
				warn(log, String.format("Stream at %#x: length %#x, trailer says %#x",
					recOffset, data.length, wantLen));
			}
			return data;
		}
		catch (DataFormatException e) {
			warn(log, String.format("Stream at %#x does not inflate: %s", recOffset,
				e.getMessage()));
			return null;
		}
		finally {
			inflater.end();
		}
	}

	private void createBlock(Program program, String name, long addr, byte[] data,
			String comment, boolean execute, MessageLog log, TaskMonitor monitor) {
		if (data.length == 0) {
			return;
		}
		Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(addr);
		try {
			MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, false, name,
				start, new ByteArrayInputStream(data), data.length, comment, LOADER_NAME, true,
				true, execute, log, monitor);
			if (block != null) {
				log.appendMsg(String.format("Block %s: %s-%s", block.getName(), block.getStart(),
					block.getEnd()));
			}
		}
		catch (AddressOverflowException e) {
			warn(log, "Block " + name + " does not fit in the address space: " + e.getMessage());
		}
	}

	/**
	 * Set a register (and optionally a code base context field) to the given value over the
	 * whole default address space, so that disassembly at any address sees it. The context
	 * field is only set when loaded memory lies within reach of the base (a signed 17-bit word
	 * offset); otherwise calls through the register stay computed calls.
	 */
	private void setRegisters(Program program, long value, String contextField, String register,
			MessageLog log) {
		ProgramContext ctx = program.getProgramContext();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Address min = space.getMinAddress();
		Address max = space.getMaxAddress();
		BigInteger v = BigInteger.valueOf(value);
		if (contextField != null) {
			long lo = Math.max(0, 4 * (value - 0x10000));
			long hi = Math.min(max.getOffset(), 4 * (value + 0x10000) - 1);
			if (lo > hi || !program.getMemory().intersects(space.getAddress(lo),
				space.getAddress(hi))) {
				warn(log, String.format("%s = %#x: no loaded memory within reach of this code " +
					"base; calls through %s left unresolved", register, value, register));
				contextField = null;
			}
		}
		for (String name : new String[] { contextField, register }) {
			if (name == null) {
				continue;
			}
			Register reg = ctx.getRegister(name);
			if (reg == null) {
				warn(log, "Language has no register " + name + "; value " +
					Long.toHexString(value) + " not set");
				continue;
			}
			try {
				ctx.setValue(reg, min, max, v);
				log.appendMsg(String.format("Set %s = %#x over %s-%s", name, value, min, max));
			}
			catch (ContextChangeException e) {
				warn(log, "Could not set " + name + ": " + e.getMessage());
			}
		}
	}

	private void setEntry(Program program, long value, MessageLog log) {
		long byteAddr = 4 * (value & 0x3FFFFFFFL);
		Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(byteAddr);
		log.appendMsg(String.format("Entry point %s (word %#x, flag bit 30 = %d)", addr,
			value & 0x3FFFFFFFL, (value >> 30) & 1));
		if (!program.getMemory().contains(addr)) {
			warn(log, "Entry point " + addr + " is not in loaded memory");
		}
		SymbolTable symbols = program.getSymbolTable();
		try {
			symbols.createLabel(addr, "entry", SourceType.IMPORTED);
		}
		catch (Exception e) {
			warn(log, "Could not create entry label: " + e.getMessage());
		}
		symbols.addExternalEntryPoint(addr);
	}

	// ---- helpers ----

	private static void warn(MessageLog log, String msg) {
		log.appendMsg("WARNING: " + msg);
	}

	static long u32(byte[] b, int off) {
		return ((b[off] & 0xFFL) << 24) | ((b[off + 1] & 0xFFL) << 16) |
			((b[off + 2] & 0xFFL) << 8) | (b[off + 3] & 0xFFL);
	}

	static long u32le(byte[] b, int off) {
		return ((b[off + 3] & 0xFFL) << 24) | ((b[off + 2] & 0xFFL) << 16) |
			((b[off + 1] & 0xFFL) << 8) | (b[off] & 0xFFL);
	}

	static int u16(byte[] b, int off) {
		return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
	}

	private static String cString(byte[] b, int off, int max) {
		int end = off;
		while (end < off + max && end < b.length && b[end] != 0) {
			end++;
		}
		return new String(b, off, end - off, StandardCharsets.US_ASCII);
	}

	private static byte[] md5(byte[] data) {
		try {
			return MessageDigest.getInstance("MD5").digest(data);
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}
}
