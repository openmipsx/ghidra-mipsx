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

// Finds MIPS-X functions that flow analysis misses (those reached only
// through function pointers) by looking for the compiler's return
// instruction. Every function ends with "jspci r31,#0,r0" and its two delay
// slots, so the word after them is almost always the next function's start
// (see docs/processor-es3890.md §6). Disassembles and creates a function
// at each such address that is not already code.
//
// Only blocks that look like code are scanned: at least one return per
// MIN_BYTES_PER_RETURN bytes.
//@category MIPS-X

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;

public class MipsXFindFunctions extends GhidraScript {

	private static final int RETURN_WORD = 0xC7C00000; // jspci r31,#0,r0
	private static final int MIN_BYTES_PER_RETURN = 2048;

	@Override
	protected void run() throws Exception {
		int created = 0;
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (!block.isInitialized() || !block.isExecute()) {
				continue;
			}
			Address start = block.getStart();
			long words = block.getSize() / 4;
			int returns = 0;
			for (long i = 0; i < words; i++) {
				if (getInt(start.add(i * 4)) == RETURN_WORD) {
					returns++;
				}
			}
			if (returns == 0 || block.getSize() / returns > MIN_BYTES_PER_RETURN) {
				println(String.format("%s: %d returns, skipped (not code)", block.getName(),
					returns));
				continue;
			}
			int here = 0;
			for (long i = 0; i + 3 < words; i++) {
				monitor.checkCancelled();
				if (getInt(start.add(i * 4)) != RETURN_WORD) {
					continue;
				}
				Address cand = start.add((i + 3) * 4);
				if (getInstructionAt(cand) != null || getFunctionContaining(cand) != null) {
					continue;
				}
				DisassembleCommand cmd = new DisassembleCommand(cand, null, true);
				if (!cmd.applyTo(currentProgram, monitor) ||
					cmd.getDisassembledAddressSet().isEmpty()) {
					continue;
				}
				if (createFunction(cand, null) != null) {
					here++;
				}
			}
			println(String.format("%s: %d returns, %d functions created", block.getName(),
				returns, here));
			created += here;
		}
		println("Functions created: " + created);
	}
}
