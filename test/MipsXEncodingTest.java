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
// Checks encodings from the processor spec against the SLEIGH module, on
// the words that test/run-encodings.sh writes. Prints MIPSX-TEST PASS or
// MIPSX-TEST FAIL lines.
//@category MIPS-X

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class MipsXEncodingTest extends GhidraScript {
	private int failures;

	private void check(boolean ok, String what) {
		println("MIPSX-TEST " + (ok ? "PASS " : "FAIL ") + what);
		if (!ok) {
			failures++;
		}
	}

	private Instruction decode(long offset) {
		Address a = toAddr(offset);
		disassemble(a);
		return getInstructionAt(a);
	}

	@Override
	protected void run() throws Exception {
		// 0x00: 0xD8040001, OP 011 compute-immediate, Spec 1 (PSW), r2 in
		// bits 21-17: movfrs psw into r2 (spec §2, §6, "movfrs destination").
		Instruction i = decode(0);
		check(i != null && i.toString().equals("movfrs psw,r2"),
			"0xD8040001 is movfrs psw,r2 (got " + i + ")");
		boolean writesR2 = false;
		if (i != null) {
			for (PcodeOp op : i.getPcode()) {
				Varnode out = op.getOutput();
				if (out != null && out.isRegister() &&
					currentProgram.getRegister(out).getName().equals("r2")) {
					writesR2 = true;
				}
			}
		}
		check(writesR2, "movfrs psw,r2 writes r2");

		// 0x04: 0xD8002001, r2 in bits 16-12 as earlier spec versions had it.
		// Bits 16-12 of movfrs are 0, so this is not an instruction.
		Instruction j = decode(4);
		check(j == null, "0xD8002001 (bits 16-12 set) does not decode (got " + j + ")");

		println("MIPSX-TEST " + (failures == 0 ? "OK" : failures + " FAILED"));
	}
}
