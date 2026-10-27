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

// Decompiles every function in the current program to C and writes the
// result to a directory given as the first script argument. Produces one
// combined "decompiled.c" (functions in address order, each preceded by a
// comment with its entry address) and a "decompile.log" listing any
// functions the decompiler could not complete.
//
// The output is decompiled vendor code. If you are doing clean-room work,
// treat it as dirty-side material and write it somewhere the clean side
// never reads.
//
// Headless use:
//   -postScript DecompileToC.java <output-directory>
//@category MIPS-X

import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DecompileToC extends GhidraScript {

	private static final int TIMEOUT_SECONDS = 60;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			println("DecompileToC: output directory argument required");
			return;
		}
		Path outDir = Paths.get(args[0]);
		Files.createDirectories(outDir);
		Path cFile = outDir.resolve("decompiled.c");
		Path logFile = outDir.resolve("decompile.log");

		DecompInterface decomp = new DecompInterface();
		decomp.setOptions(new DecompileOptions());
		if (!decomp.openProgram(currentProgram)) {
			println("DecompileToC: failed to open program: " + decomp.getLastMessage());
			return;
		}

		int ok = 0;
		int failed = 0;
		try (PrintWriter c = new PrintWriter(Files.newBufferedWriter(cFile));
				PrintWriter log = new PrintWriter(Files.newBufferedWriter(logFile))) {

			c.println("// Decompiled from " + currentProgram.getName());
			c.println("// Decompiled vendor code: do not redistribute");
			c.println();

			FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
			while (functions.hasNext()) {
				monitor.checkCancelled();
				Function fn = functions.next();
				String where = fn.getEntryPoint().toString();
				DecompileResults res = decomp.decompileFunction(fn, TIMEOUT_SECONDS, monitor);
				if (res != null && res.decompileCompleted()
						&& res.getDecompiledFunction() != null) {
					c.println("// " + fn.getName() + " @ " + where);
					c.println(res.getDecompiledFunction().getC());
					c.println();
					ok++;
				} else {
					String msg = res == null ? "no result" : res.getErrorMessage();
					log.println(where + "\t" + fn.getName() + "\t" + msg);
					failed++;
				}
				if ((ok + failed) % 100 == 0) {
					println(String.format("DecompileToC: %d done (%d failed)", ok + failed,
						failed));
				}
			}
			log.println("decompiled " + ok + ", failed " + failed);
		} finally {
			decomp.dispose();
		}
		println(String.format("DecompileToC: wrote %d functions to %s (%d failed)", ok,
			cFile, failed));
	}
}
