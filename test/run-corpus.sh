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

# Imports each firmware image given on the command line into a throwaway
# Ghidra project, runs auto-analysis, MipsXFindFunctions and a second
# analysis pass, and prints one MIPSX-REPORT line per image and section.
#
# Usage: GHIDRA_INSTALL_DIR=/path/to/ghidra test/run-corpus.sh [-s "2 1"] image...
#
# The extension must be installed in that Ghidra (see README.md). Images may
# be bare .bin files or the vendor's Windows upgrade programs.
set -eu

: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
sections=2
if [ "${1:-}" = "-s" ]; then
	sections=$2
	shift 2
fi
here=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

for image in "$@"; do
	for s in $sections; do
		log="$work/log.txt"
		if ! "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$work" corpus \
			-import "$image" -loader SipuraLoader -loader-sectionType "$s" \
			-scriptPath "$here/ghidra_scripts" \
			-postScript MipsXFindFunctions.java \
			-postScript Reanalyze.java \
			-postScript MipsXReport.java \
			-deleteProject >"$log" 2>&1; then
			echo "FAILED $(basename "$image") section $s (log follows)"
			tail -20 "$log"
			continue
		fi
		report=$(sed -n 's/.*MIPSX-REPORT [^ ]* //p' "$log" | sed 's/ (GhidraScript).*//' | tail -1)
		warnings=$(grep -c 'WARNING: ' "$log" || true)
		echo "$(basename "$image") section=$s $report loader-warnings=$warnings"
		grep -o 'WARNING: .*' "$log" | sort -u | sed 's/^/    /' || true
	done
done
