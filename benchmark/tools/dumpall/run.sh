#!/bin/bash
# Usage: run.sh <git-url> <output-dir>
#
# dumpall reconstructs the working-tree from .git/objects and writes the
# files into <output-dir>/<host>_<port>/ — it does NOT preserve a `.git/`
# tree. After it runs we lift those files up to <output-dir>/ so the
# benchmark comparator (which expects repo-root-relative paths) can see
# them, and we drop a stub `.git/` so _find_recovered_repo anchors here.
URL="$1"
OUTPUT_DIR="$2"

mkdir -p "$OUTPUT_DIR"
dumpall -u "${URL}/.git/" -o "$OUTPUT_DIR" -f 2>&1 || true

# Flatten the single host-named subdir up one level.
shopt -s nullglob dotglob
for sub in "$OUTPUT_DIR"/*/; do
    if [ -d "$sub" ] && [ "$(basename "$sub")" != ".git" ]; then
        mv "$sub"* "$OUTPUT_DIR"/ 2>/dev/null || true
        rmdir "$sub" 2>/dev/null || true
    fi
done

# Stub .git/ so the runner's _find_recovered_repo treats $OUTPUT_DIR as
# the recovered repo root rather than walking further. dumpall genuinely
# does not recover .git/ contents — features that depend on it (commits,
# branches, tags, refs, reflogs, stashes) will correctly score 0%.
mkdir -p "$OUTPUT_DIR/.git"
: > "$OUTPUT_DIR/.git/HEAD"
