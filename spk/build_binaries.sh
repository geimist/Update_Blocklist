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

# Go 1.26.0 bis 1.26.2 ruft auf 32-Bit-ARM den time64-Futex auf. Synology-Kernel 3.2
# (armadaxp, z.B. DS214+) belegt diese Nummer mit einem eigenen Aufruf. Der Runtime
# bricht dann mit "futexwakeup returned -1" ab. Behoben ab Go 1.26.3.
# Die toolchain-Zeile in go.mod zieht mindestens Go 1.26.10, sofern GOTOOLCHAIN
# nicht auf local steht. Diese Prüfung fängt den local-Fall ab.
min_go=1.26.3
go_version_ok() {
    awk -v have="$1" -v need="$2" 'BEGIN {
        n1 = split(have, h, ".")
        n2 = split(need, n, ".")
        for (i = 1; i <= 3; i++) {
            hv = (i <= n1 ? h[i] + 0 : 0)
            nv = (i <= n2 ? n[i] + 0 : 0)
            if (hv > nv) exit 0
            if (hv < nv) exit 1
        }
        exit 0
    }'
}
go_version_of() {
    raw=$1
    raw=${raw#go}
    printf '%s\n' "${raw%%[^0-9.]*}"
}
got_raw=$(cd "$root" && "$GO" env GOVERSION)
got=$(go_version_of "$got_raw")
if ! go_version_ok "$got" "$min_go"; then
    echo "Go ${got_raw} ist zu alt. Mindestens Go ${min_go} (toolchain-Zeile in go.mod)." >&2
    echo "GOTOOLCHAIN=local mit einem älteren Compiler ist hier nicht zulässig." >&2
    exit 1
fi
echo "go ${got_raw}"

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

for bin in "$api_dir"/ab-api-*; do
    stamp=$("$GO" version -m "$bin" | awk 'NR == 1 { print $NF }')
    built=$(go_version_of "$stamp")
    if ! go_version_ok "$built" "$min_go"; then
        echo "$bin wurde mit Go ${stamp} gebaut, mindestens Go ${min_go} ist nötig." >&2
        exit 1
    fi
done
echo "binaries in $helper_dir and $api_dir"
