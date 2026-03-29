#!/bin/bash
# Usage: run.sh <git-url> <output-dir>
set -e

URL="$1"
OUTPUT_DIR="$2"

mkdir -p "$OUTPUT_DIR"
# GitTools Dumper downloads .git folder contents
bash /opt/gittools/Dumper/gitdumper.sh "${URL}/.git/" "$OUTPUT_DIR"
# GitTools Extractor recovers source code from .git
bash /opt/gittools/Extractor/extractor.sh "$OUTPUT_DIR" "${OUTPUT_DIR}_extracted" 2>/dev/null || true
# Copy extracted files back if extraction succeeded
if [ -d "${OUTPUT_DIR}_extracted" ]; then
    cp -rn "${OUTPUT_DIR}_extracted"/*/ "$OUTPUT_DIR/" 2>/dev/null || true
fi
