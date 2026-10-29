#!/bin/sh
# Cross-compile ab-helper for DSM 7. Static musl, same idea as synOCR.
# sqlite3 itself stays the DSM binary; this program only calls it.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
repo=$(cd "$root/.." && pwd)
src="$root/helper/ab-helper.c"
out_dir="$root/APP/bin/helper"
mkdir -p "$out_dir" "$repo/.tools/zig-cache"
export ZIG_GLOBAL_CACHE_DIR="$repo/.tools/zig-cache"
export ZIG_LOCAL_CACHE_DIR="$repo/.tools/zig-cache"

if ! command -v zig >/dev/null 2>&1; then
    echo "zig nicht gefunden" >&2
    exit 1
fi

build_one() {
    name=$1
    target=$2
    echo "build helper $name"
    zig cc -target "$target" -O2 -static -s -Wall -Wextra -Werror \
        -o "$out_dir/ab-helper-$name" "$src"
    chmod 755 "$out_dir/ab-helper-$name"
}

build_one x86_64 x86_64-linux-musl
build_one i686 x86-linux-musl
build_one armv7 arm-linux-musleabihf
build_one aarch64 aarch64-linux-musl

if command -v file >/dev/null 2>&1; then
    file "$out_dir"/ab-helper-*
fi
ls -lh "$out_dir"/ab-helper-*
