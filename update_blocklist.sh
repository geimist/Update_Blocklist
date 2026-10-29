#!/bin/bash
# shellcheck disable=SC1091

#################################################################################################################################################
#                                                                                                                                               #
# Script import IP's from blocklist.de                                                                                                          #
#                                                                                                                                               #
# https://www.synology-forum.de/threads/staendige-anmeldeversuche-am-dsm.122250/page-2#post-1015901               #
# version 0.1 by Ruedi61        15.11.2016 / DSM 6.0.3                                                                                          #
# version 0.2 by AndiHeitzer    18.09.2019 / DSM 6.2.1  ➜ add further Vars for DB                                                               #
# version 0.3 by geimist        28.09.2019 / DSM 6.2.1  ➜ add stats / loglevel / speed improvement / delete expired IPs                         #
# version 0.4 by geimist        24.05.2022 / DSM 7.1    ➜ speed improvement over 5x                                                             #
#                                                         (for 10000 IPs only 107 seconds are needed instead of 658 seconds)                    #
# version 0.5 by geimist        16.10.2022 / DSM 7.1    ➜ permanent block does not work properly                                                #
# version 0.6 by geimist        17.10.2022 / DSM 7.1    ➜ GeoIP verification added (ATTENTION: this reduces the speed significantly)            #
# version 0.7 by geimist        02.09.2023 / DSM 7.2    ➜ Error while checking the download of the block list                                   #
#                                                       ➜ Adjustment of the code so that it passes shellcheck                                   #
# version 0.8 by geimist        11.09.2023 / DSM 7.2    ➜ loop with defined number of attempts (MAX_ATTEMPTS) to load the block list            #
# version 0.9 by geimist        23.03.2024 / DSM 7.2    ➜ The exit status 1 (abnormal) will only be one time if blocklist.de is not available.  #
# version 0.9.1 by geimist      24.03.2024 / DSM 7.2    ➜ An additional message is displayed when the script has been run normally again.       #
# version 0.10 by geimist       29.04.2025 / DSM 7.2    ➜ improved timout                                                                       #
# version 0.10.1 by geimist     29.04.2025 / DSM 7.2    ➜ minor bugfixes                                                                       #
# version 0.11 by geimist       16.08.2026 / DSM 7.4    ➜ fix: trap/exit-codes, pipefail, SQL-guard, IPv4-validation order, GeoIP batch        #
# version 0.12 by geimist       28.10.2026 / DSM 7.4    ➜ exit 1/2 only after consecutive failures / successes                                  #
# version 0.13 by geimist       29.10.2026 / DSM 7.4    ➜ optional IPv6 import (IMPORT_IPV6=1), off by default                                  #
#                                                                                                                                               #
#################################################################################################################################################

# Deny=1 ➜ Blacklist / Deny=0 ➜ Whitelist
    Deny=1
# Download from www.blocklist.de | Select Typ: {all} {ssh} {mail} {apache} {imap} {ftp} {sip} {bots} {strongips} {ircbot} {bruteforcelogin} 
    BLOCKLIST_TYP="all" 
# Delete IP after x Day's OR use 0 for permanent block 
    DELETE_IP_AFTER=7
# 0 = IPv4 only / 1 = also import IPv6
    IMPORT_IPV6=0
# Loglevel 1: Show Stats at the bottom / Loglevel 2: Show all / Loglevel 0: disable
    LOGLEVEL=1
    PROGRESSBAR=0
    MAX_ATTEMPTS=5  # max. number of attempts to load the block list
# Notification hysteresis (consecutive runs). Stops exit 1/2 flapping when blocklist.de is only briefly unreachable.
# FAIL_ALERT_AFTER=1      → first failed run already reports exit 1
# RECOVERY_ALERT_AFTER=3  → exit 2 only after 3 successful runs in a row
    FAIL_ALERT_AFTER=3
    RECOVERY_ALERT_AFTER=6
# Performance-Debug: 1 = Phasen-Timing als NDJSON (Datei neben dem Skript)
    DEBUG_PERF=0
    DEBUG_PERF_LOG=""   # leer = ${own_path}/update_blocklist_perf.ndjson; sonst eigener Pfad

# 0=Single Host / 1=? / 2=IP-Range (META must be set) / 3=subnetmask (META must be set)
    TYPE=0 
# e.g. subnetmask / upper IP-Range
    META=''

# GeoIP implementation:
    # defined countries are: blockonly | blockother | off
    # blockonly     only the defined countries should be included
    # blockother    only all other countries are to be included
    useGeoIP="off"
    GeoIP_DB="/var/db/geoip-database/GeoLite2-City.mmdb"
    countries=(DE CN)    # ISO style - example: countries=(DE CN)

#############################################################################################################################################
# Do NOT change after here!
    skipByGeoIP=0
    attempts=0
# Persisted across runs via synosetkeyvalue (rewrites these assignments in this file).
# FailStreak: consecutive failed runs since the last success
# SuccessStreak: consecutive successful runs while an alert is open
# AlertState: 0 = no open alert / 1 = exit 1 was already reported
    FailStreak=0
    SuccessStreak=0
    AlertState=0

    [[ "${FAIL_ALERT_AFTER}" =~ ^[1-9][0-9]*$ ]] || FAIL_ALERT_AFTER=1
    [[ "${RECOVERY_ALERT_AFTER}" =~ ^[1-9][0-9]*$ ]] || RECOVERY_ALERT_AFTER=3
    [[ "${FailStreak}" =~ ^[0-9]+$ ]] || FailStreak=0
    [[ "${SuccessStreak}" =~ ^[0-9]+$ ]] || SuccessStreak=0
    [ "${AlertState}" = 1 ] || AlertState=0

if [ "$(whoami)" != "root" ]; then
    echo "WARNING: this script must run from root!" >&2
    exit 1
fi

# Pipeline-Exit-Status zuverlässig auswerten (z. B. Download-Fehler erkennen)
set -o pipefail

# Python3 Environment for GeoIP:
    own_path="${0%/*}"
    [ "${own_path}" = "${0}" ] && own_path="."
    python3_env="${own_path}/update_blocklist_python3_env"

# Performance-Instrumentierung (DEBUG_PERF=1): Phasen-Timing als NDJSON + [PERF] auf stderr
_perf_now_ms() {
    local t
    t=$(date +%s%3N 2>/dev/null) || true
    if [[ "${t}" =~ ^[0-9]+$ ]]; then
        printf '%s' "${t}"
    else
        printf '%s' "$(($(date +%s) * 1000))"
    fi
}
_perf_phase_start_ms=0
_perf_run_id="run_$(date +%s)"
_perf_log_file=""
perf_init() {
    [ "${DEBUG_PERF}" = 1 ] || return 0
    if [ -n "${DEBUG_PERF_LOG}" ]; then
        _perf_log_file="${DEBUG_PERF_LOG}"
    else
        _perf_log_file="${own_path}/update_blocklist_perf.ndjson"
    fi
    : > "${_perf_log_file}" 2>/dev/null || _perf_log_file="/tmp/update_blocklist_perf.ndjson"
    : > "${_perf_log_file}"
    perf_log "init" "start" "logFile=${_perf_log_file}" "bash=${BASH_VERSION:-unknown}" "host=$(uname -n 2>/dev/null || echo unknown)" "arch=$(uname -m 2>/dev/null || echo unknown)"
}
perf_log() {
    # usage: perf_log phase event [key=value ...]
    [ "${DEBUG_PERF}" = 1 ] || return 0
    local phase="$1" event="$2"
    shift 2
    local ts data_json pair k v first=1
    ts=$(_perf_now_ms)
    data_json="{"
    for pair in "$@"; do
        k="${pair%%=*}"
        v="${pair#*=}"
        v="${v//\\/\\\\}"
        v="${v//\"/\\\"}"
        if [ "${first}" = 1 ]; then
            first=0
        else
            data_json+=","
        fi
        data_json+="\"${k}\":\"${v}\""
    done
    data_json+="}"
    printf '{"runId":"%s","phase":"%s","event":"%s","data":%s,"timestamp":%s}\n' \
        "${_perf_run_id}" "${phase}" "${event}" "${data_json}" "${ts}" >> "${_perf_log_file}" 2>/dev/null || true
}
perf_phase_begin() {
    [ "${DEBUG_PERF}" = 1 ] || return 0
    _perf_phase_start_ms=$(_perf_now_ms)
    perf_log "$1" "begin"
}
perf_phase_end() {
    [ "${DEBUG_PERF}" = 1 ] || return 0
    local phase="$1"
    shift
    local now dur
    now=$(_perf_now_ms)
    dur=$((now - _perf_phase_start_ms))
    perf_log "${phase}" "end" "durationMs=${dur}" "$@"
    printf '[PERF] %-28s %8s ms' "${phase}" "${dur}" >&2
    if [ "$#" -gt 0 ]; then
        printf '  (%s)' "$*" >&2
    fi
    printf '\n' >&2
}
    python_env_version=1        # is written to an info file after setting up the python env to skip a full check of the python env on each run
    python_module_list=( geoip2 )

    perf_init

    if [ "${useGeoIP}" = blockonly ] || [ "${useGeoIP}" = blockother ]; then
        if [ ! -f "${GeoIP_DB}" ]; then
            echo "(GeoIP database not found at ${GeoIP_DB} / GeoIP filter disabled)"
            useGeoIP=off
        elif [ ! "$(which python3)" ]; then
            echo "(Python3 is not installed / GeoIP filter disabled)"
            useGeoIP=off
        else
            [ ! -d "${python3_env}" ] && python3 -m venv "${python3_env}"
            source "${python3_env}/bin/activate"

            if [ "$(head -n1 "${python3_env}/python_env_version" 2>/dev/null )" != "${python_env_version}" ]; then
    
            # check / install pip:
            # ---------------------------------------------------------------------
                if ! python3 -m pip --version > /dev/null  2>&1 ; then
                    printf "  Python3 pip was not found and will be now installed ➜ "
                    # install pip:
                    tmp_log1=$(python3 -m ensurepip --default-pip)
                    # upgrade pip:
                    tmp_log2=$(python3 -m pip install --upgrade pip)
                    # check install:
                    if python3 -m pip --version > /dev/null  2>&1 ; then
                        echo "ok"
                    else
                        echo "failed ! ! ! (please install Python3 pip manually)"
                        echo "  install log:"
                        echo "${tmp_log1}" | sed -e "s/^/  /g"
                        echo "${tmp_log2}" | sed -e "s/^/  /g"
                        exit 1
                    fi
                else
                    if python3 -m pip list 2>&1 | grep -q "version.*is available" ; then
                        printf '%s\n' "  pip already installed ($(python3 -m pip --version)) / upgrade available ..."
                        python3 -m pip install --upgrade pip | sed -e "s/^/  /g"
                    fi
                fi
    
                printf "\nread installed python modules:\n"
    
                moduleList=$(python3 -m pip list 2>/dev/null)
    
                # check / install python modules:
                # ---------------------------------------------------------------------
                for module in "${python_module_list[@]}"; do
                    moduleName=$(echo "${module}" | awk -F'=' '{print $1}' )
    
                    unset tmp_log1
                    printf '%s' "  ➜ check python module \"${module}\": ➜ "
                    if !  grep -qi "${moduleName}" <<< "${moduleList}"; then
                        printf '%s' "${module} was not found and will be installed ➜ "
    
                        # install module:
                        tmp_log1=$(python3 -m pip install "${module}")
    
                        # check install:
                        if grep -qi "${moduleName}" <<< "$(python3 -m pip list 2>/dev/null)" ; then
                            echo "ok"
                        else
                            echo "failed ! ! ! (please install ${module} manually)"
                            echo "  install log:" && echo "${tmp_log1}" | sed -e "s/^/  /g"
                            exit 1
                        fi
                    else
                        printf "ok\n"
                    fi
                done
    
                echo "${python_env_version}" > "${python3_env}/python_env_version"
                source "${python3_env}/bin/activate"
                printf "\n"
            fi
            source "${python3_env}/bin/activate"
        fi
    # python3 -m pip list 2>/dev/null
    fi

persist_var() {
    # Write key=value back into this script only when the value changed.
    # synosetkeyvalue rewrites the matching assignment; unchanged runs stay untouched.
    local key="$1" value="$2"
    [ "${!key}" = "${value}" ] && return 0
    printf -v "${key}" '%s' "${value}"
    synosetkeyvalue "$0" "${key}" "${value}"
}

function_exit() {
    # Exit 1 only after FAIL_ALERT_AFTER consecutive failures.
    # Further failures stay silent (exit 0) until a recovery has been reported.
    local ExitCode="$1"

    if [ "${ExitCode}" != 1 ]; then
        return 0
    fi

    persist_var SuccessStreak 0

    if [ "${AlertState}" != 1 ]; then
        persist_var FailStreak "$((FailStreak + 1))"
        if [ "${FailStreak}" -ge "${FAIL_ALERT_AFTER}" ]; then
            persist_var AlertState 1
            exit 1
        fi
    fi

    exit 0
}

finish_run() {
    # Successful run. Exit 2 only after RECOVERY_ALERT_AFTER consecutive successes
    # while an alert is still open. Otherwise exit 0 (no DSM notification).
    persist_var FailStreak 0

    if [ "${AlertState}" = 1 ]; then
        persist_var SuccessStreak "$((SuccessStreak + 1))"
        if [ "${SuccessStreak}" -ge "${RECOVERY_ALERT_AFTER}" ]; then
            persist_var AlertState 0
            persist_var SuccessStreak 0
            printf "\n\nINFO: The script could be executed normally again.\n"
            exit 2
        fi
        printf "\n\nINFO: The script ran normally (%s/%s consecutive successes, recovery not reported yet).\n" \
            "${SuccessStreak}" "${RECOVERY_ALERT_AFTER}"
    fi

    exit 0
}

setup_geoip_batch() {
    # Erzeugt ein Python-Helper-Skript, das alle IPs in einem einzigen Prozess
    # gegen die GeoIP-Datenbank prüft (statt pro IP einen Python-Prozess zu starten).
    cat > "${1}" <<'PYEOF'
import sys, geoip2.database
with geoip2.database.Reader(sys.argv[1]) as reader:
    for line in sys.stdin:
        ip = line.strip()
        if not ip:
            continue
        try:
            print(f"{ip}\t{reader.city(ip).country.iso_code}")
        except geoip2.errors.AddressNotFoundError:
            print(f"{ip}\tempty")
        except Exception:
            print(f"{ip}\tempty")
PYEOF
}

progressbar() {
# https://blog.cscholz.io/bash-progress-or-spinner/
# Um die Progressbar darzustellen, muss ein Zähler (_start) und der Maximalwert (_end) definiert werden.
#   _start=0
#   _end=$(wc -l $1)
#######################################
# Display a progress bar
# Arguments:
#   $1 Current loop number
#   $2 max. no of loops (1005)
# Returns:
#   None
#######################################

# Process data
    _progress=$((($1 * 100) / $2))
    _done=$((_progress * 4 / 10))
    _left=$((40 - _done))

# Build progressbar string lengths
_fill=$(printf "%${_done}s")
_empty=$(printf "%${_left}s")

printf "\rProgress :    [${_fill// /#}${_empty// /-}] ${_progress}%% ($1/$2)"

}

sec_to_time() {
    local seconds=$1
    local sign=""
    if [[ ${seconds:0:1} == "-" ]]; then
        seconds=${seconds:1}
        sign="-"
    fi
    local hours=$(( seconds / 3600 ))
    local minutes=$(( (seconds % 3600) / 60 ))
    seconds=$(( seconds % 60 ))
    printf "%s%02d:%02d:%02d" "$sign" $hours $minutes $seconds
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

# create temporary working directory & prepare variables
# ---------------------------------------------------------------------
    work_tmp=$(mktemp -d -t tmp.XXXXXXXXXX)
    trap 'rm -rf "${work_tmp}"' EXIT

    before_list="${work_tmp}/before.txt"
    online_list="${work_tmp}/online_list.txt"
    blocklist_list="${work_tmp}/blocklist.txt"
    sql_statement="${work_tmp}/insert_statement.sql"

    countadded=0
    db_path="/etc/synoautoblock.db"

    UNIXTIME=$(date +%s)
    
    if [ "${DELETE_IP_AFTER}" = 0 ]; then
        UNIXTIME_DELETE_IP=0
    else
        UNIXTIME_DELETE_IP=$(date -d "+${DELETE_IP_AFTER} days" +%s) 
    fi
    
    [ ! -f "${db_path}" ] && sqlite3 "${db_path}" 'CREATE TABLE AutoBlockIP(IP varchar(50) PRIMARY KEY,RecordTime date NOT NULL,ExpireTime date NOT NULL,Deny boolean NOT NULL,IPStd varchar(50) NOT NULL,Type INTEGER,Meta varchar(256))'

# count blocked IPs before:
    perf_phase_begin "sqlite_count_before"
    countbefore=$(sqlite3 "${db_path}" "SELECT count(IP) FROM AutoBlockIP WHERE Deny='1' " )
    perf_phase_end "sqlite_count_before" "countbefore=${countbefore}"

# delete IP if expired: 
    perf_phase_begin "sqlite_delete_expired"
    CountExpiredIP=$(sqlite3 "${db_path}" "SELECT count(IP) FROM AutoBlockIP WHERE ExpireTime <= $UNIXTIME AND Deny='1' AND NOT ExpireTime='0' ")
    sqlite3 "${db_path}" "DELETE FROM AutoBlockIP WHERE ExpireTime <= $UNIXTIME AND Deny='1' AND NOT ExpireTime='0' "
    perf_phase_end "sqlite_delete_expired" "expired=${CountExpiredIP}"

# current IP-list:
    perf_phase_begin "sqlite_export_before_list"
    sqlite3 -header -csv "${db_path}" "select IP FROM AutoBlockIP WHERE Deny='1' ORDER BY IP ASC;" | sed -e '1d' | sort > "${before_list}"
    _before_lines=$(wc -l < "${before_list}" | tr -d ' ')
    _db_bytes=$(wc -c < "${db_path}" 2>/dev/null | tr -d ' ')
    perf_phase_end "sqlite_export_before_list" "beforeLines=${_before_lines}" "dbBytes=${_db_bytes:-0}"

# load online IP-list:
    perf_phase_begin "download_blocklist"
    while [ "${attempts}" -lt "${MAX_ATTEMPTS}" ]; do
        timeout 60 wget -q --timeout=10 --tries=5 -nv -O - "https://lists.blocklist.de/lists/${BLOCKLIST_TYP}.txt" | sort | uniq > "${online_list}"
        exit_status=$?
        # Check the exit status and file size
        if [ "${exit_status}" -eq 0 ] && [ -s "${online_list}" ]; then
            # The list was loaded successfully.
            break
        else
            attempts=$((attempts+1))
            echo "Failure on attempt ${attempts}"
            if [ "${attempts}" -lt "${MAX_ATTEMPTS}" ]; then
                # "Next try ..."
                sleep 5  # Waiting time before next attempt (optional)
            else
                echo "Block list could not be loaded. Maximum number (${MAX_ATTEMPTS}) of attempts reached."
                function_exit 1
            fi
        fi
    done
    [ "${IMPORT_IPV6}" = 1 ] || IMPORT_IPV6=0
    filter_addrs list < "${online_list}" | sort -u > "${online_list}.norm"
    mv "${online_list}.norm" "${online_list}"
    _online_lines=$(wc -l < "${online_list}" | tr -d ' ')
    _online_bytes=$(wc -c < "${online_list}" | tr -d ' ')
    perf_phase_end "download_blocklist" "attempts=${attempts}" "onlineLines=${_online_lines}" "onlineBytes=${_online_bytes}"

    echo "count of IPs in list:         ${_online_lines}"

# filter diffs - only diffs from left to right:
    perf_phase_begin "diff_filter"
    diff "${before_list}" "${online_list}" | grep '^>' | sed -e 's/> //' > "${blocklist_list}" 
    perf_phase_end "diff_filter"

# count of diffs:
    countofdiffs=$(wc -l < "${blocklist_list}" | tr -d ' ')
    echo "${countofdiffs} IPs are different do local block list"
    perf_log "diff_count" "ready" "countofdiffs=${countofdiffs}" "useGeoIP=${useGeoIP}"

# progressbar / stats:
    progress_start=0
    progress_end="${countofdiffs}"

    : > "${work_tmp}/accepted.txt"

# GeoIP: alle Diffs in EINEM Python-Prozess prüfen (statt pro IP) und in Map ablegen
    declare -A geoip_map
    if [ "${useGeoIP}" = blockonly ] || [ "${useGeoIP}" = blockother ]; then
        perf_phase_begin "geoip_batch_lookup"
        geoip_helper="${work_tmp}/geoip_lookup.py"
        geoip_results="${work_tmp}/geoip_results.txt"
        setup_geoip_batch "${geoip_helper}"
        python3 "${geoip_helper}" "${GeoIP_DB}" < "${blocklist_list}" > "${geoip_results}"
        while IFS=$'\t' read -r gip gcountry; do
            geoip_map["${gip}"]="${gcountry}"
        done < "${geoip_results}"
        perf_phase_end "geoip_batch_lookup"
    fi

_loop_i=0
_loop_t0=$(_perf_now_ms)
perf_phase_begin "loop_process_diffs"

while read -r BLOCKED_IP ; do
    if [ "${DEBUG_PERF}" = 1 ]; then
        _loop_i=$((_loop_i + 1))
        if [ $((_loop_i % 1000)) -eq 0 ]; then
            _now=$(_perf_now_ms)
            perf_log "loop_process_diffs" "checkpoint" "processed=${_loop_i}" "countadded=${countadded}" "elapsedMs=$((_now - _loop_t0))"
            printf '[PERF] loop checkpoint             %8s ms  (processed=%s countadded=%s)\n' "$((_now - _loop_t0))" "${_loop_i}" "${countadded}" >&2
        fi
    fi

    # Addresses were normalized above. Anything else is skipped.
    if [[ ! "${BLOCKED_IP}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] \
        && { [ "${IMPORT_IPV6}" != 1 ] || [[ ! "${BLOCKED_IP}" =~ ^[0-9a-f:]+$ ]] || [[ "${BLOCKED_IP}" != *:* ]]; }; then
        [ "${LOGLEVEL}" -eq 2 ] && echo "skip invalid IP: ${BLOCKED_IP}"
        continue
    fi

    # 2) GeoIP-Filter (Lookup aus vorberechneter Map)
    if [ "${useGeoIP}" = blockonly ] || [ "${useGeoIP}" = blockother ]; then
        request_GeoIP_result="${geoip_map[${BLOCKED_IP}]:-empty}"

        if [ "${useGeoIP}" = blockonly ] && echo "${countries[@]}" | grep -qiv "${request_GeoIP_result}" ; then
            skipByGeoIP=$((skipByGeoIP+1))
            progress_start=$((progress_start+1))
            [ "${LOGLEVEL}" -eq 2 ] && echo "continue - ${BLOCKED_IP} - country: ${request_GeoIP_result}"
            continue
        elif [ "${useGeoIP}" = blockother ] && echo "${countries[@]}" | grep -qi "${request_GeoIP_result}" ; then
            skipByGeoIP=$((skipByGeoIP+1))
            progress_start=$((progress_start+1))
            [ "${LOGLEVEL}" -eq 2 ] && echo "continue - ${BLOCKED_IP} - country: ${request_GeoIP_result}"
            continue
        fi
    fi

    printf '%s\n' "${BLOCKED_IP}" >> "${work_tmp}/accepted.txt"
    countadded=$((countadded + 1))

    if [ "${LOGLEVEL}" -eq 2 ]; then
        echo "IP added to Database!    -->  ${BLOCKED_IP}"
    elif [ "${LOGLEVEL}" -eq 1 ] && [ "${PROGRESSBAR}" -eq 1 ]; then
        # progressbar:
        progress_start=$((progress_start+1))
        progressbar "${progress_start}" "${progress_end}"
    fi

done < "${blocklist_list}"
perf_phase_end "loop_process_diffs" "processed=${_loop_i:-0}" "countadded=${countadded}"

# SQL nur schreiben, wenn tatsächlich Zeilen hinzugefügt wurden (sonst Syntaxfehler)
if [ "${countadded}" -ge 1 ] ; then
    perf_phase_begin "sqlite_prepare_sql"
    AB_RECORD="${UNIXTIME}" AB_EXPIRE="${UNIXTIME_DELETE_IP}" AB_DENY="${Deny}" AB_TYPE="${TYPE}" AB_META="${META}" \
        filter_addrs sql < "${work_tmp}/accepted.txt" > "${sql_statement}"
    _sql_bytes=$(wc -c < "${sql_statement}" | tr -d ' ')
    perf_phase_end "sqlite_prepare_sql" "sqlBytes=${_sql_bytes}"
    printf "\n\nwrite DB ...\n"
    perf_phase_begin "sqlite_insert"
    sqlite3 "${db_path}" < "${sql_statement}"
    perf_phase_end "sqlite_insert" "countadded=${countadded}"
fi

perf_log "run" "complete" "totalSec=$(($(date +%s)-UNIXTIME))" "countofdiffs=${countofdiffs}" "countadded=${countadded}" "countbefore=${countbefore}" "expired=${CountExpiredIP}" "perfLog=${_perf_log_file}"
[ "${DEBUG_PERF}" = 1 ] && printf '[PERF] log file: %s\n' "${_perf_log_file}" >&2

# stats …
if [ "${LOGLEVEL}" -eq 1 ] || [ "${LOGLEVEL}" -eq 2 ]; then 
    echo -e; echo -e; 
    echo "stats:--------------------------------"
    echo "duration of the process:      $(sec_to_time "$(($(date +%s)-UNIXTIME))" )" 
    echo "count of IPs in list:         $(wc -l < "${online_list}" | tr -d ' ')"
    echo "count of diffs:               ${countofdiffs}"
    echo "added IPs:                    ${countadded}"
    echo "IP skipped by GeoIP:          ${skipByGeoIP}"
    echo "expired IPs (deleted):        ${CountExpiredIP} (set expiry time: ${DELETE_IP_AFTER} days)"
    echo "blocked IPs:                  before: ${countbefore} / current: $(sqlite3 "${db_path}" "SELECT count(IP) FROM AutoBlockIP WHERE Deny='1' " )"
fi

finish_run
