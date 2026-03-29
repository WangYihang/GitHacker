#!/bin/bash
# Usage: run.sh <git-url> <output-dir>
set -e

URL="$1"
OUTPUT_DIR="$2"

mkdir -p "$OUTPUT_DIR"
git-dumper "${URL}/.git/" "$OUTPUT_DIR" || true
