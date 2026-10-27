#!/usr/bin/env bash
# macOS double-clickable launcher (Finder requires the .command extension to
# make a shell script runnable by double-click). Just forwards to run.sh.
cd "$(dirname "${BASH_SOURCE[0]}")"
exec ./run.sh
