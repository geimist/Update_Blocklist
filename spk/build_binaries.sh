#!/bin/sh
# Baut ab-api in Go und ab-helper in C (DSM-sqlite3) für vier Architekturen.
set -eu
root=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$root/.." && pwd)
GO="${GO:-}"
if [ -z "$GO" ]; then
    if command -v go >/dev/null 2>&1; then
        GO=$(command -v go)
    elif [ -x "$repo/.tools/go/bin/go" ]; then
        GO="$repo/.tools/go/bin/go"
    else
        echo "go nicht gefunden" >&2
        exit 1
    fi
fi

helper_dir="$root/APP/bin/helper"
api_dir="$root/APP/bin/ui-bin"
mkdir -p "$helper_dir" "$api_dir"
"$root/helper/build.sh"

build_one() {
    arch_name=$1
    goarch=$2
    goarm=${3:-}
    echo "build $arch_name"
    (
        cd "$root"
        export CGO_ENABLED=0 GOOS=linux GOARCH="$goarch"
        if [ -n "$goarm" ]; then
            export GOARM="$goarm"
        fi
        "$GO" build -trimpath -ldflags "-s -w" -o "$api_dir/ab-api-$arch_name" ./cmd/ab-api
    )
}

build_one x86_64 amd64
build_one i686 386
build_one armv7 arm 7
build_one aarch64 arm64
echo "binaries in $helper_dir and $api_dir"
