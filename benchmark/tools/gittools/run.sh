#!/bin/bash
# Usage: run.sh <git-url> <output-dir>
URL="$1"
OUTPUT_DIR="$2"

mkdir -p "$OUTPUT_DIR"

# GitTools Dumper downloads .git folder contents directly to output dir
bash /opt/gittools/Dumper/gitdumper.sh "${URL}/.git/" "$OUTPUT_DIR/" 2>&1 || true
