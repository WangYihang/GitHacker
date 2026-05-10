#!/bin/bash
# Usage: run.sh <git-url> <output-dir>
URL="$1"
OUTPUT_DIR="$2"

mkdir -p "$OUTPUT_DIR"
dumpall -u "${URL}/.git/" -o "$OUTPUT_DIR" -f 2>&1 || true
