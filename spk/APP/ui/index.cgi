#!/bin/sh
# DSM ruft diese Datei über den Symlink webman/3rdparty/AutoBan auf.
# Der zeigt auf target/ui, deshalb nicht relativ zu $0 nach der Binary suchen.
# Kein blindes exec: stirbt die Binary ohne HTTP-Antwort, zeigt DSM seine 404-Seite.
set -eu

target=/var/packages/AutoBan/target
var=/var/packages/AutoBan/var
log="$var/log/cgi.log"

case "$(uname -m)" in
    x86_64) bin=ab-api-x86_64 ;;
    i686|i386) bin=ab-api-i686 ;;
    aarch64|arm64) bin=ab-api-aarch64 ;;
    armv7*|armv6l) bin=ab-api-armv7 ;;
    *) bin=ab-api-x86_64 ;;
esac
exe="$target/bin/ui-bin/$bin"

trim_log() {
    [ -f "$log" ] || return 0
    lines=$(wc -l < "$log" | tr -d ' ')
    [ "${lines:-0}" -gt 400 ] || return 0
    tail -n 400 "$log" > "${log}.$$" && mv "${log}.$$" "$log"
}

note_failure() {
    platform=$(cat /proc/syno_platform 2>/dev/null || true)
    [ -n "${platform:-}" ] || platform=unknown
    {
        echo "$(date '+%Y-%m-%d %H:%M:%S') ui failed rc=$1 bin=$bin uname=$(uname -m) kernel=$(uname -r) platform=$platform"
        if [ -s "${err:-}" ]; then
            cat "$err"
        fi
    } >>"$log" 2>/dev/null || true
    trim_log || true
    logger -t AutoBan -p user.err "UI-Binary ${bin} Exit ${1} auf $(uname -m) Kernel $(uname -r). Log: ${log}" 2>/dev/null || true
    printf 'Status: 500 Internal Server Error\r\n'
    printf 'Content-Type: text/plain; charset=utf-8\r\n'
    printf '\r\n'
    printf 'AutoBan konnte die Oberfläche nicht starten.\n'
    printf 'Binary: %s\nExit: %s\nArchitektur: %s\nKernel: %s\nPlattform: %s\nLog: %s\n' \
        "$bin" "$1" "$(uname -m)" "$(uname -r)" "$platform" "$log"
}

out=""
err=""
if mkdir -p "$var/log" "$var/tmp" 2>/dev/null; then
    out=$(mktemp "$var/tmp/cgi-out.XXXXXX" 2>/dev/null || true)
    err=$(mktemp "$var/tmp/cgi-err.XXXXXX" 2>/dev/null || true)
fi

# Ohne beschreibbares Temp-Verzeichnis bleibt das bisherige Verhalten.
if [ -z "$out" ] || [ -z "$err" ]; then
    exec "$exe"
fi
trap 'rm -f "$out" "$err"' EXIT

rc=0
if [ ! -x "$exe" ]; then
    rc=127
    printf 'not executable: %s\n' "$exe" >"$err"
else
    "$exe" >"$out" 2>"$err" || rc=$?
fi

if [ -s "$out" ]; then
    if [ "$rc" -ne 0 ] && [ -s "$err" ]; then
        {
            echo "$(date '+%Y-%m-%d %H:%M:%S') ui exit rc=$rc bin=$bin (Antwort wurde trotzdem gesendet)"
            cat "$err"
        } >>"$log" 2>/dev/null || true
        trim_log || true
    fi
    cat "$out"
    exit 0
fi

note_failure "$rc"
exit 0
