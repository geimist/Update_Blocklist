#!/bin/bash
# shellcheck disable=SC1091

#################################################################################################################################################
# AutoBan-Paketskript (DSM 7 SPK). Kanonische Datei: spk/update_blocklist.sh                                                                   #
# Das Standalone-Skript im Repo-Root (update_blocklist.sh) bleibt in der klassischen Form für Nutzer ohne SPK.                                 #
# Änderungen an der Ablauf-Logik hier und dort parallel nachziehen.                                                                             #
#                                                                                                                                               #
# Im Paket: Einstellungen/Zustand/Statistik in /var/packages/AutoBan/var/app.db; System-DB nur über setuid ab-helper.                            #
#                                                                                                                                               #
# version 0.13 by geimist       29.10.2026 / DSM 7  ➜ Paketmodus AutoBan, app.db, Helper, Log getrennt von Statistik                            #
# version 0.14 by geimist       29.10.2026 / DSM 7  ➜ optional IPv6 import (import_ipv6), off by default                                       #
#################################################################################################################################################

# --- Standalone-Voreinstellungen (im Paket kommen die Werte aus app.db) ---
# Deny=1 Blacklist / Deny=0 Whitelist
Deny=1
# blocklist.de Typ: all ssh mail apache imap ftp sip bots strongips ircbot bruteforcelogin
BLOCKLIST_TYP="all"
# Hauptliste. Leer lässt die Adresse aus dem Typ entstehen.
SOURCE_URL=""
# Zusätzliche Listen, eine http(s)-URL pro Zeile. Im Paket steht hier ein JSON-Array.
EXTRA_SOURCES=""
# IP nach x Tagen löschen, 0 = dauerhaft
DELETE_IP_AFTER=7
# 0 = nur IPv4, 1 = IPv4 und IPv6
IMPORT_IPV6=0
# 0 still / 1 Kurzinfo / 2 ausführlich
LOGLEVEL=1
PROGRESSBAR=0
MAX_ATTEMPTS=5
FAIL_ALERT_AFTER=3
RECOVERY_ALERT_AFTER=6
DEBUG_PERF=0
# 0 einzelner Host / 2 Bereich / 3 Netzmaske (META muss dann gesetzt sein)
TYPE=0
META=''
# GeoIP: off | blockonly | blockother
useGeoIP="off"
GeoIP_DB="/var/db/geoip-database/GeoLite2-City.mmdb"
countries=(DE CN)

# Zustand über Läufe hinweg (Standalone: synosetkeyvalue schreibt diese Zeilen neu)
FailStreak=0
SuccessStreak=0
AlertState=0

# --- Ab hier Ablauf. Paketpfade und Helfer ------------------------------------------------

PACKAGE_MODE=0
PKG_VAR=""
PKG_TARGET=""
APP_DB=""
LOG_FILE=""
SYS_DB="/etc/synoautoblock.db"
HELPER="${AUTOBAN_HELPER:-}"
BACKUP_DIR=""
work_tmp=""
STARTED=0
STARTED_MS=0

skipByGeoIP=0
attempts=0
countadded=0
countofdiffs=0
countbefore=0
countafter=0
CountExpiredIP=0
online_count=0

resolve_self() {
    if command -v readlink >/dev/null 2>&1 && readlink -f "$1" >/dev/null 2>&1; then
        readlink -f "$1"
        return
    fi
    python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$1"
}

detect_mode() {
    local src
    src=$(resolve_self "$0")
    if [ -n "${AUTOBAN_ROOT:-}" ]; then
        PACKAGE_MODE=1
        PKG_VAR="${AUTOBAN_ROOT}/var"
        PKG_TARGET="${AUTOBAN_ROOT}/target"
    elif [[ "$src" == *"/var/packages/AutoBan/"* || "$src" == *"@appstore/AutoBan/"* ]]; then
        PACKAGE_MODE=1
        PKG_VAR="/var/packages/AutoBan/var"
        PKG_TARGET="${src%/bin/*}"
    fi
    if [ "$PACKAGE_MODE" = 1 ]; then
        APP_DB="${PKG_VAR}/app.db"
        LOG_FILE="${PKG_VAR}/log/autoban.log"
        BACKUP_DIR="${PKG_VAR}/db_backups"
        SYS_DB="${AUTOBAN_SYSDB:-/etc/synoautoblock.db}"
        if [ -z "$HELPER" ]; then
            HELPER="$(helper_path)"
        fi
    fi
}

helper_path() {
    local machine bin
    machine=$(uname -m)
    case "$machine" in
        x86_64) bin="ab-helper-x86_64" ;;
        i686|i386) bin="ab-helper-i686" ;;
        aarch64|arm64) bin="ab-helper-aarch64" ;;
        armv7*|armv6l) bin="ab-helper-armv7" ;;
        *) bin="ab-helper-x86_64" ;;
    esac
    printf '%s\n' "${PKG_TARGET}/bin/helper/${bin}"
}

log() {
    local level="$1"
    shift
    local line show=0
    line="$(date '+%Y-%m-%d %H:%M:%S') ${level} $*"
    case "$level" in
        ERROR|WARN) show=1 ;;
        INFO) [ "${LOGLEVEL}" -ge 1 ] && show=1 ;;
        DEBUG) [ "${LOGLEVEL}" -ge 2 ] && show=1 ;;
    esac
    [ "$show" = 1 ] || return 0
    if [ "$PACKAGE_MODE" = 1 ] && [ -n "$LOG_FILE" ]; then
        printf '%s\n' "$line" >> "$LOG_FILE"
    fi
    printf '%s\n' "$*" >&2
}

# shellcheck disable=SC2329  # aufgerufen über trap cleanup
trim_log() {
    [ "$PACKAGE_MODE" = 1 ] && [ -f "$LOG_FILE" ] || return 0
    local lines
    lines=$(wc -l < "$LOG_FILE" | tr -d ' ')
    [ "${lines:-0}" -gt 1000 ] || return 0
    tail -n 1000 "$LOG_FILE" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "$LOG_FILE"
}

init_app_db() {
    mkdir -p "${PKG_VAR}/log" "${PKG_VAR}/db_backups" "${PKG_VAR}/tmp" "${PKG_VAR}/perf"
    # Gleiches Schema wie spk/internal/appdb/schema.sql
    sqlite3 "$APP_DB" <<'SQL'
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL,
  online_count INTEGER NOT NULL,
  diffs INTEGER NOT NULL,
  added INTEGER NOT NULL,
  expired INTEGER NOT NULL,
  geoip_skip INTEGER NOT NULL,
  count_before INTEGER NOT NULL,
  count_after INTEGER NOT NULL,
  status TEXT NOT NULL,
  message TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS run_days (
  day TEXT PRIMARY KEY,
  online_count INTEGER NOT NULL,
  added INTEGER NOT NULL,
  count_after INTEGER NOT NULL
);
INSERT OR IGNORE INTO settings(key, value) VALUES
  ('interval_minutes','10'),('blocklist_typ','all'),
  ('source_url','https://lists.blocklist.de/lists/all.txt'),('extra_sources','[]'),
  ('delete_ip_after','7'),('loglevel','1'),('geoip_mode','off'),
  ('geoip_countries','["DE","CN"]'),('max_attempts','5'),
  ('fail_alert_after','3'),('recovery_alert_after','6'),('notify_lang','ger'),
  ('scheduler_enabled','1'),('debug_perf','0'),('deny','1'),
  ('progressbar','0'),('type','0'),('meta',''),
  ('geoip_db','/var/db/geoip-database/GeoLite2-City.mmdb'),
  ('import_ipv6','0');
INSERT OR IGNORE INTO state(key, value) VALUES
  ('fail_streak','0'),('success_streak','0'),('alert_state','0');
SQL
    chmod 600 "$APP_DB" 2>/dev/null || true
}

setting_get() {
    sqlite3 "$APP_DB" "SELECT value FROM settings WHERE key='$1';"
}

state_get() {
    local val
    val=$(sqlite3 "$APP_DB" "SELECT value FROM state WHERE key='$1';")
    if [[ "$val" =~ ^[0-9]+$ ]]; then
        printf '%s' "$val"
    else
        printf '%s' "$2"
    fi
}

state_set() {
    local key="$1" value="$2"
    [[ "$value" =~ ^[0-9]+$ ]] || return 1
    sqlite3 "$APP_DB" "INSERT INTO state(key,value) VALUES('${key}','${value}') ON CONFLICT(key) DO UPDATE SET value='${value}';"
}

json_lines() {
    # Gibt JSON-Array-Elemente zeilenweise aus. Ohne Python: eine Zeile pro bereits getrenntem Eintrag.
    local raw="$1"
    if [ -z "$raw" ] || [ "$raw" = "[]" ]; then
        return 0
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import json,sys
raw=sys.stdin.read().strip()
try:
    data=json.loads(raw)
except Exception:
    data=None
if isinstance(data, list):
    print("\n".join(str(x) for x in data))
else:
    print(raw)' <<<"$raw"
    else
        printf '%s\n' "$raw" | tr -d '[]"' | tr ',' '\n'
    fi
}

load_package_config() {
    init_app_db
    Deny=$(setting_get deny)
    BLOCKLIST_TYP=$(setting_get blocklist_typ)
    SOURCE_URL=$(setting_get source_url)
    EXTRA_SOURCES=$(setting_get extra_sources)
    DELETE_IP_AFTER=$(setting_get delete_ip_after)
    LOGLEVEL=$(setting_get loglevel)
    PROGRESSBAR=$(setting_get progressbar)
    MAX_ATTEMPTS=$(setting_get max_attempts)
    FAIL_ALERT_AFTER=$(setting_get fail_alert_after)
    RECOVERY_ALERT_AFTER=$(setting_get recovery_alert_after)
    NOTIFY_LANG=$(setting_get notify_lang)
    DEBUG_PERF=$(setting_get debug_perf)
    TYPE=$(setting_get type)
    META=$(setting_get meta)
    useGeoIP=$(setting_get geoip_mode)
    GeoIP_DB=$(setting_get geoip_db)
    IMPORT_IPV6=$(setting_get import_ipv6)
    local country_lines=()
    while IFS= read -r line; do
        [ -n "$line" ] && country_lines+=("$line")
    done < <(json_lines "$(setting_get geoip_countries)")
    [ "${#country_lines[@]}" -gt 0 ] && countries=("${country_lines[@]}")
    FailStreak=$(state_get fail_streak 0)
    SuccessStreak=$(state_get success_streak 0)
    AlertState=$(state_get alert_state 0)
}

# --- Systemdatenbank: Standalone spricht sqlite3, das Paket nur den Helper ---

helper_call() {
    if [ ! -x "$HELPER" ]; then
        log ERROR "ab-helper nicht gefunden oder nicht ausführbar (${HELPER})"
        exit 1
    fi
    "$HELPER" --db "$SYS_DB" --backup-dir "$BACKUP_DIR" --tmp-dir "${PKG_VAR}/tmp" "$@"
}

db_ensure() {
    if [ "$PACKAGE_MODE" = 1 ]; then
        helper_call ensure-schema
    else
        [ -f "$SYS_DB" ] || sqlite3 "$SYS_DB" 'CREATE TABLE AutoBlockIP(IP varchar(50) PRIMARY KEY,RecordTime date NOT NULL,ExpireTime date NOT NULL,Deny boolean NOT NULL,IPStd varchar(50) NOT NULL,Type INTEGER,Meta varchar(256))'
    fi
}

db_backup() {
    [ "$PACKAGE_MODE" = 1 ] || return 0
    [ -f "$SYS_DB" ] || return 0
    helper_call backup
}

db_count() {
    if [ "$PACKAGE_MODE" = 1 ]; then
        helper_call count
    else
        sqlite3 "$SYS_DB" "SELECT count(IP) FROM AutoBlockIP WHERE Deny='1'"
    fi
}

db_export() {
    local dest="$1"
    if [ "$PACKAGE_MODE" = 1 ]; then
        helper_call export-deny | sort > "$dest"
    else
        sqlite3 -header -csv "$SYS_DB" "SELECT IP FROM AutoBlockIP WHERE Deny='1' ORDER BY IP ASC;" | sed -e '1d' | sort > "$dest"
    fi
}

db_delete_expired() {
    local now="$1"
    if [ "$PACKAGE_MODE" = 1 ]; then
        helper_call delete-expired "$now"
    else
        local n
        n=$(sqlite3 "$SYS_DB" "SELECT count(IP) FROM AutoBlockIP WHERE ExpireTime <= ${now} AND Deny='1' AND NOT ExpireTime='0'")
        sqlite3 "$SYS_DB" "DELETE FROM AutoBlockIP WHERE ExpireTime <= ${now} AND Deny='1' AND NOT ExpireTime='0'"
        printf '%s\n' "$n"
    fi
}

filter_addrs() {
    # list writes canonical addresses. sql writes one INSERT statement.
    # IPv6 stays out unless IMPORT_IPV6=1. sql reads AB_RECORD, AB_EXPIRE, AB_DENY, AB_TYPE, AB_META.
    local job="$1" use6=0
    [ "${IMPORT_IPV6}" = 1 ] && use6=1
    awk -v ipv6="$use6" -v job="$job" '
function hexdigits(n, width,    digits, out, d, v) {
    digits = "0123456789abcdef"
    v = n + 0
    out = ""
    if (v < 0) v = 0
    if (v == 0) out = "0"
    while (v > 0) {
        d = v % 16
        out = substr(digits, d + 1, 1) out
        v = int(v / 16)
    }
    while (width > 0 && length(out) < width) out = "0" out
    return out
}
function hexup(n, width,    s, i, c, up) {
    s = hexdigits(n, width)
    up = ""
    for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (c >= "a" && c <= "f") c = substr("ABCDEF", index("abcdef", c), 1)
        up = up c
    }
    return up
}
function is_ipv4(s,    a, i, n, v, ch, c) {
    n = split(s, a, ".")
    if (n != 4) return 0
    for (i = 1; i <= 4; i++) {
        if (a[i] == "" || length(a[i]) > 3) return 0
        v = 0
        for (ch = 1; ch <= length(a[i]); ch++) {
            c = substr(a[i], ch, 1)
            if (c < "0" || c > "9") return 0
            v = v * 10 + (c - "0")
        }
        if (v > 255) return 0
        a[i] = v
    }
    return 1
}
function v4_text(s,    a) {
    split(s, a, ".")
    return (a[1] + 0) "." (a[2] + 0) "." (a[3] + 0) "." (a[4] + 0)
}
function v4_std(s,    a) {
    split(s, a, ".")
    return "0000:0000:0000:0000:0000:FFFF:" hexup(a[1] + 0, 2) hexup(a[2] + 0, 2) ":" hexup(a[3] + 0, 2) hexup(a[4] + 0, 2)
}
function parse_v6(s, g, head, tail,    pos, n, seen, hn, tn, i, v, digits, c, h, v1, v2, zeros, idx, dot, oct, a) {
    if (s == "" || index(s, "%") > 0 || length(s) > 45 || index(s, ":") == 0) return 0
    n = length(s)
    pos = 1
    seen = 0
    hn = 0
    tn = 0
    if (substr(s, 1, 1) == ":") {
        if (substr(s, 2, 1) != ":") return 0
        seen = 1
        pos = 3
        if (pos > n) {
            for (i = 1; i <= 8; i++) g[i] = 0
            return 1
        }
    }
    while (pos <= n) {
        if (substr(s, pos, 1) == ":") return 0
        dot = 0
        for (i = pos; i <= n; i++) {
            c = substr(s, i, 1)
            if (c == ":") break
            if (c == ".") { dot = 1; break }
        }
        if (dot) {
            oct = substr(s, pos)
            if (!is_ipv4(oct)) return 0
            split(oct, a, ".")
            v1 = (a[1] + 0) * 256 + (a[2] + 0)
            v2 = (a[3] + 0) * 256 + (a[4] + 0)
            if (seen) {
                if (tn > 6) return 0
                tn++; tail[tn] = v1
                tn++; tail[tn] = v2
            } else {
                if (hn > 6) return 0
                hn++; head[hn] = v1
                hn++; head[hn] = v2
            }
            break
        }
        v = 0
        digits = 0
        while (pos <= n) {
            c = tolower(substr(s, pos, 1))
            h = index("0123456789abcdef", c)
            if (h == 0) break
            v = v * 16 + (h - 1)
            digits++
            pos++
            if (digits > 4) return 0
        }
        if (digits == 0) return 0
        if (seen) {
            if (tn >= 8) return 0
            tn++
            tail[tn] = v
        } else {
            if (hn >= 8) return 0
            hn++
            head[hn] = v
        }
        if (pos > n) break
        if (substr(s, pos, 1) != ":") return 0
        pos++
        if (pos <= n && substr(s, pos, 1) == ":") {
            if (seen) return 0
            seen = 1
            pos++
            if (pos > n) break
        } else if (pos > n) return 0
    }
    if (!seen) {
        if (hn != 8) return 0
        for (i = 1; i <= 8; i++) g[i] = head[i]
        return 1
    }
    if (hn + tn > 7) return 0
    zeros = 8 - hn - tn
    idx = 1
    for (i = 1; i <= hn; i++) { g[idx] = head[i]; idx++ }
    for (i = 1; i <= zeros; i++) { g[idx] = 0; idx++ }
    for (i = 1; i <= tn; i++) { g[idx] = tail[i]; idx++ }
    return idx == 9
}
function is_mapped(g) {
    return g[1] == 0 && g[2] == 0 && g[3] == 0 && g[4] == 0 && g[5] == 0 && g[6] == 65535
}
function mapped_v4(g) {
    return int(g[7] / 256) "." (g[7] % 256) "." int(g[8] / 256) "." (g[8] % 256)
}
function canon_v6(g,    i, j, best, bestlen, len, out, need) {
    best = -1
    bestlen = 0
    i = 1
    while (i <= 8) {
        if (g[i] != 0) { i++; continue }
        j = i
        while (j <= 8 && g[j] == 0) j++
        len = j - i
        if (len > bestlen) { best = i; bestlen = len }
        i = j
    }
    if (bestlen < 2) best = -1
    out = ""
    need = 0
    i = 1
    while (i <= 8) {
        if (best > 0 && i == best) {
            out = out ":"
            i += bestlen
            if (i > 8) { out = out ":"; break }
            out = out ":"
            need = 0
            continue
        }
        if (need) out = out ":"
        out = out hexdigits(g[i], 0)
        need = 1
        i++
    }
    return out
}
function v6_std(g) {
    return hexup(g[1], 4) ":" hexup(g[2], 4) ":" hexup(g[3], 4) ":" hexup(g[4], 4) ":" hexup(g[5], 4) ":" hexup(g[6], 4) ":" hexup(g[7], 4) ":" hexup(g[8], 4)
}
function canonical(s, stdp, g,    ip) {
    sub(/\r$/, "", s)
    if (index(s, ":") == 0) {
        if (!is_ipv4(s)) return ""
        ip = v4_text(s)
        stdp[0] = v4_std(ip)
        return ip
    }
    if (!parse_v6(s, g)) return ""
    if (is_mapped(g)) {
        ip = mapped_v4(g)
        stdp[0] = v4_std(ip)
        return ip
    }
    if (ipv6 != 1) return ""
    ip = canon_v6(g)
    stdp[0] = v6_std(g)
    return ip
}
BEGIN {
    n = 0
    if (job == "sql") {
        rec = ENVIRON["AB_RECORD"]
        expire = ENVIRON["AB_EXPIRE"]
        denyv = ENVIRON["AB_DENY"]
        typ = ENVIRON["AB_TYPE"]
        meta = ENVIRON["AB_META"]
        gsub(/\047/, "\047\047", meta)
    }
}
{
    line = $0
    sub(/^[ \t]+/, "", line)
    sub(/[ \t]+$/, "", line)
    if (line == "") next
    ip = canonical(line, std)
    if (ip == "") next
    if (job == "sql") {
        n++
        if (n == 1)
            printf "INSERT OR IGNORE INTO AutoBlockIP (IP, RecordTime, ExpireTime, Deny, IPStd, Type, Meta) VALUES "
        else
            printf ","
        printf "(\047%s\047,\047%s\047,\047%s\047,\047%s\047,\047%s\047,\047%s\047,\047%s\047)", ip, rec, expire, denyv, std[0], typ, meta
    } else
        print ip
}
END {
    if (job == "sql" && n > 0) printf ";\n"
}
'
}

db_insert_file() {
    local file="$1" record="$2" expire="$3"
    if [ ! -s "$file" ]; then
        printf '0\n'
        return 0
    fi
    if [ "$PACKAGE_MODE" = 1 ]; then
        helper_call insert-batch "$file" "$record" "$expire" "$Deny" "$TYPE" "$META"
    else
        local sql="${work_tmp}/insert.sql"
        AB_RECORD="$record" AB_EXPIRE="$expire" AB_DENY="$Deny" AB_TYPE="$TYPE" AB_META="$META" \
            filter_addrs sql < "$file" > "$sql"
        sqlite3 "$SYS_DB" < "$sql"
        wc -l < "$file" | tr -d ' '
    fi
}

future_unix() {
    local days="$1"
    if [ "$days" = "0" ]; then
        printf '0\n'
        return
    fi
    if date -d "+${days} days" +%s >/dev/null 2>&1; then
        date -d "+${days} days" +%s
    else
        python3 -c 'import time,sys; print(int(time.time())+int(sys.argv[1])*86400)' "$days"
    fi
}

fetch_to() {
    local url="$1" dest="$2"
    if [ -f "$url" ]; then
        cp "$url" "$dest"
        return $?
    fi
    if command -v wget >/dev/null 2>&1; then
        if command -v timeout >/dev/null 2>&1; then
            timeout 60 wget -q --timeout=10 --tries=5 -O "$dest" "$url"
        else
            wget -q --timeout=10 --tries=5 -O "$dest" "$url"
        fi
    else
        curl -fsSL --max-time 60 -o "$dest" "$url"
    fi
}

download_primary() {
    local url dest="${work_tmp}/primary.txt"
    if [ -n "${AUTOBAN_SOURCE_URL:-}" ]; then
        url="$AUTOBAN_SOURCE_URL"
    elif [ -n "${SOURCE_URL:-}" ]; then
        url="$SOURCE_URL"
    else
        url="https://lists.blocklist.de/lists/${BLOCKLIST_TYP}.txt"
    fi
    attempts=0
    while [ "$attempts" -lt "$MAX_ATTEMPTS" ]; do
        if fetch_to "$url" "$dest" && [ -s "$dest" ]; then
            cat "$dest"
            return 0
        fi
        attempts=$((attempts + 1))
        log WARN "Quelle nicht geladen (Versuch ${attempts}/${MAX_ATTEMPTS}): ${url}"
        [ "$attempts" -lt "$MAX_ATTEMPTS" ] && sleep 5
    done
    return 1
}

download_extra() {
    local url dest="${work_tmp}/extra.txt" line
    [ -n "$EXTRA_SOURCES" ] || return 0
    while IFS= read -r line; do
        url=$(printf '%s' "$line" | tr -d '[:space:]')
        [ -n "$url" ] || continue
        if fetch_to "$url" "$dest" && [ -s "$dest" ]; then
            cat "$dest"
            log INFO "Zusatzquelle geladen: ${url}"
        else
            log WARN "Zusatzquelle übersprungen: ${url}"
        fi
        rm -f "$dest"
    done < <(json_lines "$EXTRA_SOURCES")
}

setup_geoip_batch() {
    cat > "$1" <<'PYEOF'
import sys, geoip2.database
with geoip2.database.Reader(sys.argv[1]) as reader:
    for line in sys.stdin:
        ip = line.strip()
        if not ip:
            continue
        try:
            print(f"{ip}\t{reader.city(ip).country.iso_code}")
        except Exception:
            print(f"{ip}\tempty")
PYEOF
}

progressbar() {
    local _progress _done _left _fill _empty
    _progress=$((($1 * 100) / $2))
    _done=$((_progress * 4 / 10))
    _left=$((40 - _done))
    _fill=$(printf "%${_done}s")
    _empty=$(printf "%${_left}s")
    printf "\rProgress :    [%s%s] %s%% (%s/%s)" "${_fill// /#}" "${_empty// /-}" "$_progress" "$1" "$2"
}

persist_var() {
    local key="$1" value="$2"
    printf -v "$key" '%s' "$value"
    if [ "$PACKAGE_MODE" = 1 ]; then
        local dbkey
        case "$key" in
            FailStreak) dbkey=fail_streak ;;
            SuccessStreak) dbkey=success_streak ;;
            AlertState) dbkey=alert_state ;;
            *) return 0 ;;
        esac
        state_set "$dbkey" "$value"
    else
        command -v synosetkeyvalue >/dev/null 2>&1 || return 0
        synosetkeyvalue "$0" "$key" "$value"
    fi
}

sql_escape() {
    printf '%s' "$1" | sed "s/'/''/g"
}

epoch_ms() {
    local raw
    raw=$(date +%s%3N 2>/dev/null || true)
    if [[ "$raw" =~ ^[0-9]{13,}$ ]]; then
        printf '%s' "$raw"
        return
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import time; print(int(time.time()*1000))'
        return
    fi
    printf '%s000' "$(date +%s)"
}

record_run() {
    local status="$1" message="$2" dur
    [ "$PACKAGE_MODE" = 1 ] || return 0
    dur=$(( $(epoch_ms) - STARTED_MS ))
    message=$(sql_escape "$message")
    day=$(date +%Y-%m-%d)
    sqlite3 "$APP_DB" <<SQL
INSERT INTO runs(started_at,duration_ms,online_count,diffs,added,expired,geoip_skip,count_before,count_after,status,message)
VALUES(${STARTED},${dur},${online_count},${countofdiffs},${countadded},${CountExpiredIP},${skipByGeoIP},${countbefore},${countafter},'${status}','${message}');
INSERT INTO run_days(day, online_count, added, count_after)
SELECT day, online_count, added_sum, count_after FROM (
  SELECT date(started_at,'unixepoch','localtime') AS day,
         SUM(added) OVER (PARTITION BY date(started_at,'unixepoch','localtime')) AS added_sum,
         online_count, count_after,
         ROW_NUMBER() OVER (
           PARTITION BY date(started_at,'unixepoch','localtime')
           ORDER BY started_at DESC, id DESC
         ) AS rn
  FROM runs
) WHERE rn = 1
ON CONFLICT(day) DO UPDATE SET
  online_count = excluded.online_count,
  count_after = excluded.count_after,
  added = excluded.added;
DELETE FROM runs WHERE started_at < strftime('%s','now','localtime','start of day','utc','-1 day');
SQL
}

# DSM löst AutoBan:app:* über ui/texts/<sprache>/strings auf.
# import_failed und import_recovered sind dort nur "{0}". Den eigentlichen Satz
# liest das Skript aus msg_* in der gewählten Sprache und übergibt ihn als Argument.
notify_phrase() {
    local key="$1" arg="$2" lang file line val
    lang="${NOTIFY_LANG:-ger}"
    file="${PKG_TARGET}/ui/texts/${lang}/strings"
    [ -f "$file" ] || file="${PKG_TARGET}/ui/texts/enu/strings"
    [ -f "$file" ] || file="${PKG_TARGET}/ui/texts/ger/strings"
    [ -f "$file" ] || return 0
    line=$(grep -m1 "^${key}=" "$file" || true)
    val=${line#*=}
    val=${val#\"}
    val=${val%\"}
    printf '%s\n' "${val//\{0\}/$arg}"
}

notify_dsm() {
    local kind="$1" phrase key
    [ "$PACKAGE_MODE" = 1 ] || return 0
    [ -x /usr/syno/bin/synodsmnotify ] || return 0
    case "$kind" in
        fail)
            key="import_failed"
            phrase=$(notify_phrase msg_import_failed "$FailStreak")
            ;;
        recovery)
            key="import_recovered"
            phrase=$(notify_phrase msg_import_recovered "")
            ;;
        *)
            return 0
            ;;
    esac
    [ -n "$phrase" ] || return 0
    /usr/syno/bin/synodsmnotify -c "SYNO.SDS.AutoBan.Application" @administrators \
        "AutoBan:app:app_name" "AutoBan:app:${key}" "$phrase" || true
}

function_exit() {
    local ExitCode="$1"
    [ "$ExitCode" = 1 ] || return 0
    persist_var SuccessStreak 0
    if [ "$AlertState" != 1 ]; then
        persist_var FailStreak "$((FailStreak + 1))"
        if [ "$FailStreak" -ge "$FAIL_ALERT_AFTER" ]; then
            persist_var AlertState 1
            notify_dsm fail
            exit 1
        fi
    fi
    exit 0
}

finish_run() {
    local status="ok" message="ok"
    persist_var FailStreak 0
    if [ "$AlertState" = 1 ]; then
        persist_var SuccessStreak "$((SuccessStreak + 1))"
        if [ "$SuccessStreak" -ge "$RECOVERY_ALERT_AFTER" ]; then
            persist_var AlertState 0
            persist_var SuccessStreak 0
            status="recovery"
            message="recovered"
            log INFO "Die Blockliste ist wieder erreichbar."
            record_run "$status" "$message"
            notify_dsm recovery
            exit 2
        fi
        message="recovering ${SuccessStreak}/${RECOVERY_ALERT_AFTER}"
        log INFO "Lauf normal (${SuccessStreak}/${RECOVERY_ALERT_AFTER}), Meldung noch nicht gesendet."
    fi
    record_run "$status" "$message"
    exit 0
}

LOCK_DIR=""
acquire_lock() {
    local lock="${PKG_VAR:-/tmp}/run.lock"
    [ "$PACKAGE_MODE" = 1 ] || lock="/tmp/update_blocklist.lock"
    if command -v flock >/dev/null 2>&1; then
        exec 9>"$lock"
        if ! flock -n 9; then
            log INFO "Ein Lauf ist bereits aktiv."
            exit 0
        fi
    else
        LOCK_DIR="${lock}.d"
        if ! mkdir "$LOCK_DIR" 2>/dev/null; then
            log INFO "Ein Lauf ist bereits aktiv."
            exit 0
        fi
    fi
    if [ "$PACKAGE_MODE" = 1 ]; then
        printf '%s\n' "$$" > "${PKG_VAR}/run.pid"
    fi
}

# shellcheck disable=SC2329  # aufgerufen über trap EXIT
cleanup() {
    [ -n "$work_tmp" ] && rm -rf "$work_tmp"
    [ "$PACKAGE_MODE" = 1 ] && rm -f "${PKG_VAR}/run.pid"
    [ -n "$LOCK_DIR" ] && rmdir "$LOCK_DIR" 2>/dev/null || true
    trim_log
}
trap cleanup EXIT

valid_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local o
    IFS=. read -r o1 o2 o3 o4 <<<"$1"
    for o in "$o1" "$o2" "$o3" "$o4"; do
        [ "$o" -le 255 ] || return 1
    done
}

accept_ip() {
    valid_ipv4 "$1" && return 0
    [ "$IMPORT_IPV6" = 1 ] || return 1
    [[ "$1" =~ ^[0-9a-f:]+$ ]] || return 1
    [[ "$1" == *:* ]]
}

# --- Start -------------------------------------------------------------------------------------------------------

detect_mode
STARTED=$(date +%s)
STARTED_MS=$(epoch_ms)

if [ "$PACKAGE_MODE" = 1 ]; then
    load_package_config
else
    if [ "$(id -u)" != "0" ]; then
        echo "WARNING: this script must run from root!" >&2
        exit 1
    fi
fi

[[ "${FAIL_ALERT_AFTER}" =~ ^[1-9][0-9]*$ ]] || FAIL_ALERT_AFTER=1
[[ "${RECOVERY_ALERT_AFTER}" =~ ^[1-9][0-9]*$ ]] || RECOVERY_ALERT_AFTER=3
[[ "${FailStreak}" =~ ^[0-9]+$ ]] || FailStreak=0
[[ "${SuccessStreak}" =~ ^[0-9]+$ ]] || SuccessStreak=0
[ "${AlertState}" = 1 ] || AlertState=0
[[ "${MAX_ATTEMPTS}" =~ ^[1-9][0-9]*$ ]] || MAX_ATTEMPTS=5
[[ "${DELETE_IP_AFTER}" =~ ^[0-9]+$ ]] || DELETE_IP_AFTER=7
[ "$IMPORT_IPV6" = 1 ] || IMPORT_IPV6=0
[[ "${LOGLEVEL}" =~ ^[0-2]$ ]] || LOGLEVEL=1

case "$BLOCKLIST_TYP" in
    all|ssh|mail|apache|imap|ftp|sip|bots|strongips|ircbot|bruteforcelogin) ;;
    *) BLOCKLIST_TYP="all" ;;
esac

acquire_lock
log INFO "Lauf gestartet (Typ ${BLOCKLIST_TYP}, Ablauf ${DELETE_IP_AFTER} Tage, GeoIP ${useGeoIP}, IPv6 ${IMPORT_IPV6})"

if [ "$PACKAGE_MODE" = 1 ]; then
    mkdir -p "${PKG_VAR}/tmp"
    work_tmp=$(mktemp -d "${PKG_VAR}/tmp/run.XXXXXXXX")
else
    work_tmp=$(mktemp -d -t autoban.XXXXXXXX)
fi

before_list="${work_tmp}/before.txt"
online_list="${work_tmp}/online.txt"
blocklist_list="${work_tmp}/diff.txt"
insert_list="${work_tmp}/insert.txt"
: > "$insert_list"

if [ -f "$SYS_DB" ]; then
    db_backup || { record_run fail "backup failed"; log ERROR "Backup der Systemdatenbank fehlgeschlagen"; function_exit 1; }
fi
db_ensure || { record_run fail "schema failed"; log ERROR "Systemdatenbank nicht vorbereitet"; function_exit 1; }
if [ "$PACKAGE_MODE" = 1 ] && [ ! -f "${BACKUP_DIR}/pristine.db" ]; then
    db_backup || true
fi

countbefore=$(db_count | tr -d '[:space:]')
countbefore=${countbefore:-0}
UNIXTIME=$(date +%s)
UNIXTIME_DELETE_IP=$(future_unix "$DELETE_IP_AFTER")
CountExpiredIP=$(db_delete_expired "$UNIXTIME" | tr -d '[:space:]')
CountExpiredIP=${CountExpiredIP:-0}
db_export "$before_list"

if ! download_primary > "${work_tmp}/primary_raw.txt"; then
    record_run fail "download failed"
    log ERROR "Blockliste konnte nicht geladen werden."
    function_exit 1
fi
sort -u "${work_tmp}/primary_raw.txt" > "${work_tmp}/primary_sorted.txt"
download_extra | cat - "${work_tmp}/primary_sorted.txt" | filter_addrs list | sort -u > "$online_list"
online_count=$(wc -l < "$online_list" | tr -d ' ')

diff "$before_list" "$online_list" | grep '^>' | sed -e 's/^> //' > "$blocklist_list" || true
countofdiffs=$(wc -l < "$blocklist_list" | tr -d ' ')
log INFO "Online ${online_count}, neu ${countofdiffs}, abgelaufen ${CountExpiredIP}"

if [ "$useGeoIP" = "blockonly" ] || [ "$useGeoIP" = "blockother" ]; then
    if [ ! -f "$GeoIP_DB" ] || ! command -v python3 >/dev/null 2>&1; then
        log WARN "GeoIP nicht verfügbar, Filter aus"
        useGeoIP="off"
    else
        geoip_helper="${work_tmp}/geoip_lookup.py"
        geoip_results="${work_tmp}/geoip_results.txt"
        setup_geoip_batch "$geoip_helper"
        own_path="${0%/*}"
        python3_env="${own_path}/update_blocklist_python3_env"
        if [ -d "${python3_env}/bin" ]; then
            # shellcheck disable=SC1091
            source "${python3_env}/bin/activate"
        fi
        if ! python3 "$geoip_helper" "$GeoIP_DB" < "$blocklist_list" > "$geoip_results"; then
            log WARN "GeoIP-Lauf fehlgeschlagen, Filter aus"
            useGeoIP="off"
        else
            declare -A geoip_map
            while IFS=$'\t' read -r gip gcountry; do
                geoip_map["$gip"]="$gcountry"
            done < "$geoip_results"
        fi
    fi
fi

progress_start=0
progress_end="${countofdiffs:-0}"
while IFS= read -r BLOCKED_IP; do
    [ -n "$BLOCKED_IP" ] || continue
    if ! accept_ip "$BLOCKED_IP"; then
        log DEBUG "überspringe ungültige IP ${BLOCKED_IP}"
        continue
    fi
    if [ "$useGeoIP" = "blockonly" ] || [ "$useGeoIP" = "blockother" ]; then
        request_GeoIP_result="${geoip_map[$BLOCKED_IP]:-empty}"
        country_hit=0
        printf '%s\n' "${countries[@]}" | grep -qi "^${request_GeoIP_result}$" && country_hit=1
        if [ "$useGeoIP" = "blockonly" ] && [ "$country_hit" != 1 ]; then
            skipByGeoIP=$((skipByGeoIP + 1))
            log DEBUG "GeoIP skip ${BLOCKED_IP} ${request_GeoIP_result}"
            continue
        fi
        if [ "$useGeoIP" = "blockother" ] && [ "$country_hit" = 1 ]; then
            skipByGeoIP=$((skipByGeoIP + 1))
            log DEBUG "GeoIP skip ${BLOCKED_IP} ${request_GeoIP_result}"
            continue
        fi
    fi
    printf '%s\n' "$BLOCKED_IP" >> "$insert_list"
    countadded=$((countadded + 1))
    if [ "$PACKAGE_MODE" != 1 ] && [ "$LOGLEVEL" -eq 1 ] && [ "$PROGRESSBAR" -eq 1 ] && [ "${progress_end}" -gt 0 ]; then
        progress_start=$((progress_start + 1))
        progressbar "$progress_start" "$progress_end"
    fi
done < "$blocklist_list"

if [ "$countadded" -ge 1 ]; then
    log INFO "schreibe ${countadded} IPs"
    db_insert_file "$insert_list" "$UNIXTIME" "$UNIXTIME_DELETE_IP" >/dev/null
fi
countafter=$(db_count | tr -d '[:space:]')
countafter=${countafter:-0}

if [ "$PACKAGE_MODE" != 1 ] && { [ "$LOGLEVEL" -eq 1 ] || [ "$LOGLEVEL" -eq 2 ]; }; then
    printf '\nstats:--------------------------------\n'
    printf 'duration of the process:      %s\n' "$(( $(epoch_ms) - STARTED_MS ))ms"
    printf 'count of IPs in list:         %s\n' "$online_count"
    printf 'count of diffs:               %s\n' "$countofdiffs"
    printf 'added IPs:                    %s\n' "$countadded"
    printf 'IP skipped by GeoIP:          %s\n' "$skipByGeoIP"
    printf 'expired IPs (deleted):        %s (set expiry time: %s days)\n' "$CountExpiredIP" "$DELETE_IP_AFTER"
    printf 'blocked IPs:                  before: %s / current: %s\n' "$countbefore" "$countafter"
fi

log INFO "fertig: hinzugefügt ${countadded}, GeoIP übersprungen ${skipByGeoIP}, Bestand ${countbefore} -> ${countafter}"
if [ "$DEBUG_PERF" = 1 ]; then
    mkdir -p "${PKG_VAR:-$work_tmp}/perf"
    perf_file="${PKG_VAR:-$work_tmp}/perf/last.ndjson"
    printf '{"duration_ms":%s,"online":%s,"diffs":%s,"added":%s}\n' \
        "$(( $(epoch_ms) - STARTED_MS ))" "$online_count" "$countofdiffs" "$countadded" >> "$perf_file"
fi
finish_run
