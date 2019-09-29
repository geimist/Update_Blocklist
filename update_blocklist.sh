#!/bin/sh
# /volume1/homes/admin/script/update_blocklist.sh
# Script import IP's from blocklist.de 
# https://www.synology-forum.de/showthread.html?103687-Freigabe-Blockierliste-automatisch-updaten&p=837478&viewfull=1#post837478
# version 0.1 by Ruedi61,       15.11.2016 / DSM 6.0.3
# version 0.2 by AndiHeitzer,   18.09.2019 / DSM 6.2.1 > add further Vars for DB
# version 0.3 by geimist,       28.09.2019 / DSM 6.2.1 > add Stats / Loglevel / speed improvement / delete expired IPs

# Deny=1 > Blacklist / Deny=0 > Whitelist
    Deny=1
# Download from www.blocklist.de | Select Typ: {all} {ssh} {mail} {apache} {imap} {ftp} {sip} {bots} {strongips} {ircbot} {bruteforcelogin} 
    BLOCKLIST_TYP="all" 
# Delete IP after x Day's OR use 0 for permanent block 
    DELETE_IP_AFTER="7"  
# Loglevel 1: Show Stats at the bottom / Loglevel 2: Show all / Loglevel 0: disable
    LOGLEVEL=1
# 0=Single Host / 1=? / 2=IP-Range (META must be set) / 3=subnetmask (META must be set)
    TYPE=0 
# e.g. subnetmask / upper IP-Range
    META=''

############################################################################################################### 
# Do NOT change after here!

# SQL Create-Statement for restore:
# 'CREATE TABLE AutoBlockIP(IP varchar(50) PRIMARY KEY,RecordTime date NOT NULL,ExpireTime date NOT NULL,Deny boolean NOT NULL,IPStd varchr(50) NOT NULL,Type INTEGER,Meta varchar(256))'
if [ $(whoami) != "root" ]; then
    echo "WARNING: this script must run from root!" >&2
    exit 1
fi

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

countadded=0
countskipped=0
UNIXTIME=$(date +%s)
UNIXTIME_DELETE_IP=$(date -d "+$DELETE_IP_AFTER days" +%s) 

# count blocked IPs before:
    countbefore=$(sqlite3 /etc/synoautoblock.db "SELECT count(IP) FROM AutoBlockIP WHERE Deny='1' " )
# delete IP if expired: 
    CountExpiredIP=$(sqlite3 /etc/synoautoblock.db "SELECT count(IP) FROM AutoBlockIP WHERE ExpireTime <= $UNIXTIME AND Deny='1'")
    sqlite3 /etc/synoautoblock.db "DELETE FROM AutoBlockIP WHERE ExpireTime <= $UNIXTIME AND Deny='1' "
# current IP-list:
    sqlite3 -header -csv /etc/synoautoblock.db "select IP FROM AutoBlockIP WHERE Deny='1' ORDER BY 'IP' ASC;" | sed -e '1d' | sort > /tmp/before.txt
# load online IP-list:
    curl --max-time 30 -s "https://lists.blocklist.de/lists/${BLOCKLIST_TYP}.txt" | sort > /tmp/onlinelist.txt
# filter diffs:
    diff "/tmp/before.txt" "/tmp/onlinelist.txt" | grep '^>' | sed -e 's/> //' > /tmp/blocklist.txt  # only diffs from left to right
# count of diffs:
    countofdiffs=$(cat "/tmp/blocklist.txt" | grep -Eo "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" | wc -l)
    echo "$countofdiffs IPs must be importet"
    
while read BLOCKED_IP 
    do 
        # Check if IP valid 
        VALID_IPv4=$(echo "$BLOCKED_IP" | grep -Eo "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" | wc -l) 
    
        if [[ $VALID_IPv4 -eq 1 ]]; then 
            # Convert IPv4 to IPv6 :) 
            IPv4=$(echo $BLOCKED_IP | sed 's/\./ /g')
            IPv6=$(printf "0000:0000:0000:0000:0000:FFFF:%02X%02X:%02X%02X" $IPv4)
            CHECK_IF_EXISTS=$(sqlite3 /etc/synoautoblock.db "SELECT DENY FROM AutoBlockIP WHERE IP = '$BLOCKED_IP'" | wc -l)
            if [[ $CHECK_IF_EXISTS -lt 1 ]]; then 
                INSERT=$(sqlite3 /etc/synoautoblock.db "INSERT INTO AutoBlockIP VALUES ('$BLOCKED_IP','$UNIXTIME','$UNIXTIME_DELETE_IP','$Deny','$IPv6','$TYPE','$META')")
                countadded=$(( $countadded + 1 ))
                if [[ $LOGLEVEL -eq 2 ]]; then 
                    echo "IP added to Database!    -->  $BLOCKED_IP" 
                elif [[ $LOGLEVEL -eq 1 ]]; then
                    echo -n "."
                fi
            else 
                countskipped=$(( $countskipped + 1 ))
                if [[ $LOGLEVEL -eq 1 ]] || [[ $LOGLEVEL -eq 2 ]]; then 
                    echo -e; echo "IP already in Database!  -->  $BLOCKED_IP" 
                fi
            fi 
        fi 
    done < /tmp/blocklist.txt

# stats …
if [[ $LOGLEVEL -eq 1 ]] || [[ $LOGLEVEL -eq 2 ]]; then 
    echo -e; echo -e; 
    echo "stats:----------------------------------"
    echo "duration of the process:      $(sec_to_time $(expr $(date +%s)-${UNIXTIME}) )" 
    echo "count of IPs in list:         $(cat "/tmp/onlinelist.txt" | grep -Eo "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" | wc -l)"
    echo "count of diffs:               $countofdiffs"
    echo "added IPs:                    $countadded"
    echo "expired IPs (deleted):        $CountExpiredIP (set expiry time: $DELETE_IP_AFTER days)"
    echo "skipped IPs:                  $countskipped"
    echo "blocked IPs:                  before: $countbefore / current: $(sqlite3 /etc/synoautoblock.db "SELECT count(IP) FROM AutoBlockIP WHERE Deny='1' " )"
fi 

rm /tmp/blocklist.txt 
rm /tmp/before.txt
rm /tmp/onlinelist.txt

exit 0
