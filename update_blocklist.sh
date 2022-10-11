#!/bin/sh

#############################################################################################################################################
# /volume1/homes/user/script/update_blocklist.sh                                                                                            #
#                                                                                                                                           #
# Script import IP's from blocklist.de                                                                                                      #
# https://www.synology-forum.de/showthread.html?103687-Freigabe-Blockierliste-automatisch-updaten&p=837478&viewfull=1#post837478            #
# version 0.1 by Ruedi61,       15.11.2016 / DSM 6.0.3                                                                                      #
# version 0.2 by AndiHeitzer,   18.09.2019 / DSM 6.2.1  > add further Vars for DB                                                           #
# version 0.3 by geimist,       28.09.2019 / DSM 6.2.1  > add stats / loglevel / speed improvement / delete expired IPs                     #
# version 0.4 by geimist,       24.05.2022 / DSM 7.1    > speed improvement over 5x                                                         #
#                                                         (for 10000 IPs only 107 seconds are needed instead of 658 seconds)                #
#                                                                                                                                           #
#############################################################################################################################################


# Deny=1 > Blacklist / Deny=0 > Whitelist
    Deny=1
# Download from www.blocklist.de | Select Typ: {all} {ssh} {mail} {apache} {imap} {ftp} {sip} {bots} {strongips} {ircbot} {bruteforcelogin} 
    BLOCKLIST_TYP="all" 
# Delete IP after x Day's OR use 0 for permanent block 
    DELETE_IP_AFTER="5"  
# Loglevel 1: Show Stats at the bottom / Loglevel 2: Show all / Loglevel 0: disable
    LOGLEVEL=1
# 0=Single Host / 1=? / 2=IP-Range (META must be set) / 3=subnetmask (META must be set)
    TYPE=0 
# e.g. subnetmask / upper IP-Range
    META=''

#############################################################################################################################################
# Do NOT change after here!

# SQL Create-Statement for restore:
#   'CREATE TABLE AutoBlockIP(IP varchar(50) PRIMARY KEY,RecordTime date NOT NULL,ExpireTime date NOT NULL,Deny boolean NOT NULL,IPStd varchr(50) NOT NULL,Type INTEGER,Meta varchar(256))'

if [ $(whoami) != "root" ]; then
    echo "WARNING: this script must run from root!" >&2
    exit 1
fi

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
let _progress=(${1}*100/${2}*100)/100
let _done=(${_progress}*4)/10
let _left=40-$_done

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
    trap 'rm -rf "$work_tmp"; exit' EXIT

    before_list="${work_tmp}/before.txt"
    online_list="${work_tmp}/online_list.txt"
    blocklist_list="${work_tmp}/blocklist.txt"
    sql_statement="${work_tmp}/insert_statement.sql"

    countadded=0
    db_path="/etc/synoautoblock.db"

    UNIXTIME=$(date +%s)
    UNIXTIME_DELETE_IP=$(date -d "+$DELETE_IP_AFTER days" +%s) 
    [ ! -f "$db_path" ] && sqlite3 "$db_path" 'CREATE TABLE AutoBlockIP(IP varchar(50) PRIMARY KEY,RecordTime date NOT NULL,ExpireTime date NOT NULL,Deny boolean NOT NULL,IPStd varchr(50) NOT NULL,Type INTEGER,Meta varchar(256))'

# count blocked IPs before:
    countbefore=$(sqlite3 "$db_path" "SELECT count(IP) FROM AutoBlockIP WHERE Deny='1' " )

# delete IP if expired: 
    CountExpiredIP=$(sqlite3 "$db_path" "SELECT count(IP) FROM AutoBlockIP WHERE ExpireTime <= $UNIXTIME AND Deny='1'")
    sqlite3 "$db_path" "DELETE FROM AutoBlockIP WHERE ExpireTime <= $UNIXTIME AND Deny='1' "

# current IP-list:
    sqlite3 -header -csv "$db_path" "select IP FROM AutoBlockIP WHERE Deny='1' ORDER BY 'IP' ASC;" | sed -e '1d' | sort > "$before_list"

# load online IP-list:
    wget -q --timeout=30 --tries=2 -nv -O - "https://lists.blocklist.de/lists/${BLOCKLIST_TYP}.txt" | sort | uniq > "$online_list"

    if [ $(stat -c %s "$online_list") -eq 0 ] || [ ! -f "$online_list" ];then
        echo -n "WARNING: The server blocklist.de is not available! Use alternative list -> "
        wget -q --timeout=30 --tries=2 -nv -O - "https://mariushosting.com/wp-content/uploads/$(date +%Y/%m)/deny-ip-list.txt" | sort | uniq > "$online_list"
        if echo "$wgetlog" | grep -q "failed" ; then
            echo "failed!"
            exit 1
        else
            echo "OK"
        fi
    fi

# filter diffs - only diffs from left to right:
    diff "$before_list" "$online_list" | grep '^>' | sed -e 's/> //' > "$blocklist_list" 

# count of diffs:
    countofdiffs=$(cat "$blocklist_list" | grep -Eo "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" | wc -l)
    echo "$countofdiffs IPs must be importet"

# progressbar:
    progress_start=0
    progress_end=$countofdiffs

# beginn sql statement:
    # ggf. "INSERT OR REPLACE INTO ..." https://www.sqlite.org/lang_insert.html
    echo "INSERT OR IGNORE INTO AutoBlockIP ('IP', 'RecordTime', 'ExpireTime', 'Deny', 'IPStd', 'Type', 'Meta') VALUES " > "$sql_statement"

while read BLOCKED_IP ; do 
    # Check if IP valid 
    VALID_IPv4=$(echo "$BLOCKED_IP" | grep -Eo "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" | wc -l) 

    if [[ "$VALID_IPv4" -eq 1 ]]; then 
        # Convert IPv4 to IPv6 :) 
        IPv4=$(echo $BLOCKED_IP | sed 's/\./ /g')
        IPv6=$(printf "0000:0000:0000:0000:0000:FFFF:%02X%02X:%02X%02X" $IPv4)

        echo "('$BLOCKED_IP','$UNIXTIME','$UNIXTIME_DELETE_IP','$Deny','$IPv6','$TYPE','$META')," >> "$sql_statement"

        countadded=$(( $countadded + 1 ))
        if [[ $LOGLEVEL -eq 2 ]]; then 
            echo "IP added to Database!    -->  $BLOCKED_IP" 
        elif [[ $LOGLEVEL -eq 1 ]]; then
            # progressbar:
            let progress_start=progress_start+1
            progressbar ${progress_start} ${progress_end}
        fi
    fi 
done < "$blocklist_list"


if [ "$countofdiffs" -ge 1 ] ; then
    last_entry=$(cat "$sql_statement" | tail -n1)
    sed -i  "s/$last_entry/${last_entry%,};/g" "$sql_statement"
    printf "\n\nwrite DB ...\n"
    sqlite3 "$db_path" < "$sql_statement"
fi

# stats …
if [[ $LOGLEVEL -eq 1 ]] || [[ $LOGLEVEL -eq 2 ]]; then 
    echo -e; echo -e; 
    echo "stats:--------------------------------"
    echo "duration of the process:      $(sec_to_time $(expr $(date +%s)-${UNIXTIME}) )" 
    echo "count of IPs in list:         $(cat "$online_list" | grep -Eo "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" | wc -l)"
    echo "count of diffs:               $countofdiffs"
    echo "added IPs:                    $countadded"
    echo "expired IPs (deleted):        $CountExpiredIP (set expiry time: $DELETE_IP_AFTER days)"
    echo "blocked IPs:                  before: $countbefore / current: $(sqlite3 "$db_path" "SELECT count(IP) FROM AutoBlockIP WHERE Deny='1' " )"
fi 


exit 0
