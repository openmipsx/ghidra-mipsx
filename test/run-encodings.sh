#!/bin/sh
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

# Decodes a few words written from the processor spec with the extension
# zip built in dist/ (newest first), installed into a throwaway Ghidra
# settings directory, and checks them with test/MipsXEncodingTest.java.
# Needs no firmware.
#
# Usage: GHIDRA_INSTALL_DIR=/path/to/ghidra test/run-encodings.sh
set -eu

: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
here=$(cd "$(dirname "$0")/.." && pwd)
zip=$(ls -t "$here"/dist/*.zip | head -1)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

ver=$(sed -n 's/^application.version=//p' "$GHIDRA_INSTALL_DIR/Ghidra/application.properties")
rel=$(sed -n 's/^application.release.name=//p' "$GHIDRA_INSTALL_DIR/Ghidra/application.properties")
# Ghidra names its settings directory <user>-ghidra when XDG_CONFIG_HOME is
# outside the home directory.
ext="$work/config/$(id -un)-ghidra/ghidra_${ver}_${rel}/Extensions"
mkdir -p "$ext" "$work/proj"
(cd "$ext" && unzip -q "$zip")

# Big-endian words: 0xD8040001 (movfrs psw,r2), 0xD8002001 (invalid).
printf '\330\004\000\001\330\000\040\001' >"$work/words.bin"

log="$work/log.txt"
XDG_CONFIG_HOME="$work/config" "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" \
	"$work/proj" enc -import "$work/words.bin" \
	-loader BinaryLoader -processor MIPS-X:BE:32:ES3890 -noanalysis \
	-scriptPath "$here/test" -postScript MipsXEncodingTest.java \
	-deleteProject >"$log" 2>&1 || { tail -20 "$log"; exit 1; }
sed -n 's/.*\(MIPSX-TEST .*\) (GhidraScript).*/\1/p' "$log"
grep -q 'MIPSX-TEST OK' "$log"
