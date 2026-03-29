#!/bin/bash
# Usage: run.sh <git-url> <output-dir>
URL="$1"
OUTPUT_DIR="$2"

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

# dvcs-ripper writes to current directory, creating .git/ in place
perl /opt/dvcs-ripper/rip-git.pl -v -u "${URL}/.git/" 2>&1 || true

# If rip-git.pl created a subdirectory (named after host), move contents up
for dir in */; do
    if [ -d "${dir}.git" ]; then
        cp -a "${dir}." . 2>/dev/null || true
        rm -rf "$dir"
    fi
done
