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

// Re-runs auto-analysis over the whole program. Used in headless mode after
// MipsXFindFunctions has created functions that only flow analysis started
// from them can reach, so their callees get disassembled and turned into
// functions too (see README.md).
//@category MIPS-X

import ghidra.app.script.GhidraScript;

public class Reanalyze extends GhidraScript {

	@Override
	protected void run() throws Exception {
		analyzeAll(currentProgram);
	}
}
