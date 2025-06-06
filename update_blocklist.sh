#!/bin/bash
# shellcheck disable=SC1091,SC2001


#################################################################################################################################################
#                                                                                                                                               #
# Script import IP's from blocklist.de                                                                                                          #
#                                                                                                                                               #
# https://www.synology-forum.de/showthread.html?103687-Freigabe-Blockierliste-automatisch-updaten&p=837478&viewfull=1#post837478                #
# version 0.1 by Ruedi61        15.11.2016 / DSM 6.0.3                                                                                          #
# version 0.2 by AndiHeitzer    18.09.2019 / DSM 6.2.1  > add further Vars for DB                                                               #
# version 0.3 by geimist        28.09.2019 / DSM 6.2.1  > add stats / loglevel / speed improvement / delete expired IPs                         #
# version 0.4 by geimist        24.05.2022 / DSM 7.1    > speed improvement over 5x                                                             #
#                                                         (for 10000 IPs only 107 seconds are needed instead of 658 seconds)                    #
# version 0.5 by geimist        16.10.2022 / DSM 7.1    > permanent block does not work properly                                                #
# version 0.6 by geimist        17.10.2022 / DSM 7.1    > GeoIP verification added (ATTENTION: this reduces the speed significantly)            #
# version 0.7 by geimist        02.09.2023 / DSM 7.2    > Error while checking the download of the block list                                   #
#                                                       > Adjustment of the code so that it passes shellcheck                                   #
# version 0.8 by geimist        11.09.2023 / DSM 7.2    > loop with defined number of attempts (MAX_ATTEMPTS) to load the block list            #
# version 0.9 by geimist        23.03.2024 / DSM 7.2    > The exit status 1 (abnormal) will only be one time if blocklist.de is not available.  #
# version 0.9.1 by geimist      24.03.2024 / DSM 7.2    > An additional message is displayed when the script has been run normally again.       #
# version 0.10 by geimist       29.04.2025 / DSM 7.2    > improved timout                                                                       #
#                                                                                                                                               #
#################################################################################################################################################

# Deny=1 > Blacklist / Deny=0 > Whitelist
    Deny=1
# Download from www.blocklist.de | Select Typ: {all} {ssh} {mail} {apache} {imap} {ftp} {sip} {bots} {strongips} {ircbot} {bruteforcelogin} 
    BLOCKLIST_TYP="all" 
# Delete IP after x Day's OR use 0 for permanent block 
    DELETE_IP_AFTER=7
# Loglevel 1: Show Stats at the bottom / Loglevel 2: Show all / Loglevel 0: disable
    LOGLEVEL=1
    PROGRESSBAR=0
    MAX_ATTEMPTS=5  # max. number of attempts to load the block list

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
    LastExitState=0

if [ "$(whoami)" != "root" ]; then
    echo "WARNING: this script must run from root!" >&2
    exit 1
fi

# Python3 Environment for GeoIP:
    own_path="${0%/*}"
    python3_env="${own_path}/update_blocklist_python3_env"
    python_env_version=1        # is written to an info file after setting up the python env to skip a full check of the python env on each run
    python_module_list=( geoip2 )

    if [ "${useGeoIP}" = blockonly ] || [ "${useGeoIP}" = blockother ]; then
        if [ ! "$(which python3)" ]; then
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
                        return 1
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
                            return 1
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

function_exit() {
    # An error message is only displayed one time if the script was terminated abnormally.
    ExitCode="$1"

    if [ "${ExitCode}" = 1 ]; then
        if [ "${LastExitState}" = 1 ]; then
            exit 0
        else
            synosetkeyvalue "$0" LastExitState 1
            exit 1
        fi
    fi
}

request_GeoIP() {
    {   echo 'import geoip2.database'
        echo "with geoip2.database.Reader('${GeoIP_DB}') as reader:"
        echo "    response = reader.city('$1')"
        echo "    print(response.country.iso_code)"
    } | python3 2>&1
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
# create temporary working directory & prepare variables
# ---------------------------------------------------------------------
    work_tmp=$(mktemp -d -t tmp.XXXXXXXXXX)
    trap 'rm -rf "${work_tmp}"; exit' EXIT

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
    
    [ ! -f "${db_path}" ] && sqlite3 "${db_path}" 'CREATE TABLE AutoBlockIP(IP varchar(50) PRIMARY KEY,RecordTime date NOT NULL,ExpireTime date NOT NULL,Deny boolean NOT NULL,IPStd varchr(50) NOT NULL,Type INTEGER,Meta varchar(256))'

# count blocked IPs before:
    countbefore=$(sqlite3 "${db_path}" "SELECT count(IP) FROM AutoBlockIP WHERE Deny='1' " )

# delete IP if expired: 
    CountExpiredIP=$(sqlite3 "${db_path}" "SELECT count(IP) FROM AutoBlockIP WHERE ExpireTime <= $UNIXTIME AND Deny='1' AND NOT ExpireTime='0' AND NOT ExpireTime='0' ")
    sqlite3 "${db_path}" "DELETE FROM AutoBlockIP WHERE ExpireTime <= $UNIXTIME AND Deny='1' AND NOT ExpireTime='0' "

# current IP-list:
    sqlite3 -header -csv "${db_path}" "select IP FROM AutoBlockIP WHERE Deny='1' ORDER BY 'IP' ASC;" | sed -e '1d' | sort > "${before_list}"

# load online IP-list:
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

    echo "count of IPs in list:         $(grep -Eo "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" "${online_list}" | wc -l)"

# filter diffs - only diffs from left to right:
    diff "${before_list}" "${online_list}" | grep '^>' | sed -e 's/> //' > "${blocklist_list}" 

# count of diffs:
    countofdiffs=$(grep -Eo "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" "${blocklist_list}" | wc -l)
    echo "${countofdiffs} IPs are different do local block list"

# progressbar / stats:
    progress_start=0
    progress_end="${countofdiffs}"

# beginn sql statement:
    # ggf. "INSERT OR REPLACE INTO ..." https://www.sqlite.org/lang_insert.html
    echo "INSERT OR IGNORE INTO AutoBlockIP ('IP', 'RecordTime', 'ExpireTime', 'Deny', 'IPStd', 'Type', 'Meta') VALUES " > "${sql_statement}"


while read -r BLOCKED_IP ; do

    # Check if IP valid 
    VALID_IPv4=$(echo "${BLOCKED_IP}" | grep -Eo "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" | wc -l) 

    # check GeoIP
    if [ "${useGeoIP}" = blockonly ] || [ "${useGeoIP}" = blockother ]; then
        request_GeoIP_result="$(request_GeoIP "${BLOCKED_IP}")"
        if grep -qi "is not in the database" <<< "${request_GeoIP_result}" ; then
            # is not in the database
            request_GeoIP_result="empty"
        fi

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

    # prepare sql statement
    if [[ "${VALID_IPv4}" -eq 1 ]]; then 
        # Convert IPv4 to IPv6 :) 
        IPv4="${BLOCKED_IP//./ }"
        # shellcheck disable=SC2086,SC2183
        IPv6=$(printf "0000:0000:0000:0000:0000:FFFF:%02X%02X:%02X%02X" ${IPv4})

        echo "('${BLOCKED_IP}','${UNIXTIME}','${UNIXTIME_DELETE_IP}','${Deny}','${IPv6}','${TYPE}','${META}')," >> "${sql_statement}"
        countadded=$((countadded + 1))

        if [ "${LOGLEVEL}" -eq 2 ]; then 
            echo "IP added to Database!    -->  ${BLOCKED_IP}" 
        elif [ "${LOGLEVEL}" -eq 1 ] && [ "${PROGRESSBAR}" -eq 1 ]; then
            # progressbar:
            progress_start=$((progress_start+1))
            progressbar "${progress_start}" "${progress_end}"
        fi
    fi

done < "${blocklist_list}"

if [ "${countofdiffs}" -ge 1 ] ; then
    last_entry=$(tail -n1 "${sql_statement}")
    sed -i  "s/${last_entry}/${last_entry%,};/g" "${sql_statement}"
    printf "\n\nwrite DB ...\n"
    sqlite3 "${db_path}" < "${sql_statement}"
fi

# stats …
if [ "${LOGLEVEL}" -eq 1 ] || [ "${LOGLEVEL}" -eq 2 ]; then 
    echo -e; echo -e; 
    echo "stats:--------------------------------"
    echo "duration of the process:      $(sec_to_time "$(($(date +%s)-UNIXTIME))" )" 
    echo "count of IPs in list:         $(grep -Eo "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" "${online_list}" | wc -l)"
    echo "count of diffs:               ${countofdiffs}"
    echo "added IPs:                    ${countadded}"
    echo "IP skipped by GeoIP:          ${skipByGeoIP}"
    echo "expired IPs (deleted):        ${CountExpiredIP} (set expiry time: ${DELETE_IP_AFTER} days)"
    echo "blocked IPs:                  before: ${countbefore} / current: $(sqlite3 "${db_path}" "SELECT count(IP) FROM AutoBlockIP WHERE Deny='1' " )"
fi

if [ "${LastExitState}" = 1 ]; then
    synosetkeyvalue "$0" LastExitState 0
    printf "\n\nINFO: The script could be executed normally again."
    exit 2
fi

exit 0
