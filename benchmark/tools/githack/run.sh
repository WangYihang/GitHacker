#!/bin/bash
# Usage: run.sh <git-url> <output-dir>
set -e

URL="$1"
OUTPUT_DIR="$2"

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"
python /opt/githack/GitHack.py "${URL}/.git/" || true
# GitHack outputs to a directory named after the host, move contents up
for dir in */; do
    if [ -d "$dir" ]; then
        cp -rn "$dir"* . 2>/dev/null || true
        rm -rf "$dir"
    fi
done
