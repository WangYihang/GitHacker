#!/bin/bash
# Usage: run.sh <git-url> <output-dir>
set -e

URL="$1"
OUTPUT_DIR="$2"

mkdir -p "$OUTPUT_DIR"
if command -v git-dumper-hh &>/dev/null; then
    git-dumper-hh "${URL}/.git/" "$OUTPUT_DIR" || true
else
    echo "git-dumper-hh binary not available (build may have failed)" >&2
    exit 1
fi
