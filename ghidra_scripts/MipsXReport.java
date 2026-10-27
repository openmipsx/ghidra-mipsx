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

// Prints one summary line for the current program: functions, instructions,
// the share of executable memory that is disassembled, and the number of
// error bookmarks (bad instructions, flow into undefined memory and so on).
// Used by test/run-corpus.sh to compare firmware images; the line starts
// with "MIPSX-REPORT" so it can be picked out of the headless log.
//@category MIPS-X

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.mem.MemoryBlock;

public class MipsXReport extends GhidraScript {

	@Override
	protected void run() throws Exception {
		AddressSet exec = new AddressSet();
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (block.isInitialized() && block.isExecute()) {
				exec.add(block.getStart(), block.getEnd());
			}
		}
		long instructions = currentProgram.getListing().getNumInstructions();
		long codeBytes = 0;
		for (var it = currentProgram.getListing().getInstructions(exec, true); it.hasNext();) {
			codeBytes += it.next().getLength();
		}
		int functions = currentProgram.getFunctionManager().getFunctionCount();
		int errors = currentProgram.getBookmarkManager().getBookmarkCount(BookmarkType.ERROR);
		String entry = currentProgram.getSymbolTable().getExternalEntryPointIterator().hasNext()
				? "yes" : "no";
		println(String.format(
			"MIPSX-REPORT %s functions=%d instructions=%d code=%.1f%% errors=%d entry=%s",
			currentProgram.getName(), functions, instructions,
			exec.getNumAddresses() == 0 ? 0.0 : 100.0 * codeBytes / exec.getNumAddresses(),
			errors, entry));
	}
}
