#!/bin/bash
# Usage: run.sh <git-url> <output-dir>
set -e

URL="$1"
OUTPUT_DIR="$2"

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"
perl /opt/dvcs-ripper/rip-git.pl -v -u "${URL}/.git/" || true
