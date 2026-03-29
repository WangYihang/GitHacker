#!/bin/bash
# Usage: run.sh <git-url> <output-dir>
URL="$1"
OUTPUT_DIR="$2"

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

# GitHack outputs to a directory named after the host
python /opt/githack/GitHack.py "${URL}/.git/" 2>&1 || true

# Move contents from hostname subdirectory up to output root
for dir in */; do
    if [ -d "$dir" ]; then
        cp -a "${dir}." . 2>/dev/null || true
        rm -rf "$dir"
    fi
done
