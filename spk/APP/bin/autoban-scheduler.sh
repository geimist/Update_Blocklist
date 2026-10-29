#!/bin/bash
# Paketinterner Zeitplan. Kein DSM-Aufgabenplaner.
# Bei scheduler_enabled=0 wird update_blocklist.sh nicht gestartet und damit
# auch keine Quellserver abgefragt. "Jetzt ausführen" in der GUI bleibt möglich.
set -u
PKG_VAR="/var/packages/AutoBan/var"
TARGET="/var/packages/AutoBan/target"
if [ -n "${AUTOBAN_ROOT:-}" ]; then
    PKG_VAR="${AUTOBAN_ROOT}/var"
    TARGET="${AUTOBAN_ROOT}/target"
fi
APP_DB="${PKG_VAR}/app.db"
SCRIPT="${TARGET}/bin/update_blocklist.sh"
PIDFILE="${PKG_VAR}/scheduler.pid"
printf '%s\n' "$$" > "$PIDFILE"
trap 'rm -f "$PIDFILE"; exit 0' TERM INT

setting() {
    sqlite3 "$APP_DB" "SELECT value FROM settings WHERE key='$1';"
}

sleep_chunked() {
    local left="$1"
    while [ "$left" -gt 0 ]; do
        if [ -f "${PKG_VAR}/scheduler.reload" ]; then
            rm -f "${PKG_VAR}/scheduler.reload"
            return
        fi
        sleep 1
        left=$((left - 1))
    done
}

# stdout/stderr zeigen auf scheduler.log. Nach dem Kürzen neu öffnen,
# sonst schreibt der Prozess weiter in die alte Datei.
trim_scheduler_log() {
    local log="${PKG_VAR}/log/scheduler.log"
    local lines
    [ -f "$log" ] || return 0
    lines=$(wc -l < "$log" | tr -d ' ')
    [ "${lines:-0}" -gt 5000 ] || return 0
    tail -n 5000 "$log" > "${log}.tmp" && mv "${log}.tmp" "$log" || return 0
    exec >>"$log" 2>&1
}

while true; do
    trim_scheduler_log
    enabled=$(setting scheduler_enabled 2>/dev/null || echo 0)
    interval=$(setting interval_minutes 2>/dev/null || echo 10)
    [[ "$interval" =~ ^[0-9]+$ ]] || interval=10
    [ "$interval" -lt 1 ] && interval=1
    if [ "$enabled" = "1" ] && [ -x "$SCRIPT" ]; then
        "$SCRIPT" || true
        sleep_chunked $((interval * 60))
    else
        # Kein Import, keine Quelle. Kurz warten, bis die Einstellung wieder an ist.
        sleep_chunked 30
    fi
done
