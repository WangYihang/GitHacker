#!/bin/bash
# Usage: run.sh <git-url> <output-dir>
URL="$1"
OUTPUT_DIR="$2"

mkdir -p "$OUTPUT_DIR"

# git_hacker.py imports sibling modules (git_dumper.py, template_parser.py,
# helpers.py), so it must run from the repo directory.
cd /opt/git-hacker
python3 git_hacker.py "${URL}/.git/" "$OUTPUT_DIR" 2>&1 || true

# Flatten any hostname subdirectory the tool may have created.
cd "$OUTPUT_DIR"
if [ ! -d ".git" ]; then
    for dir in */; do
        if [ -d "${dir}.git" ]; then
            cp -a "${dir}." . 2>/dev/null || true
            rm -rf "$dir"
        fi
    done
fi
