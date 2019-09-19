#!/bin/sh
# /volume1/DEV/update_blocklist.sh
# Script import IP's from blocklist.de into DSM Auto-Block
# https://www.synology-forum.de/showthread.html?103687-Freigabe-Blockierliste-automatisch-updaten&p=837478&viewfull=1#post837478
# version 0.1 by Ruedi61,       15.11.2016 / DSM 6.0.3
# version 0.2 by AndiHeitzer,   18.09.2019 / DSM 6.2.1 > add further Vars for DB
# version 0.3 by geimist,       19.09.2019 / DSM 6.2.2 > enlarge Stats / Loglevel

# TYPE=0 > Blacklist / TYPE=3 > Whitelist
TYPE=0 

META='' 

# Download from www.blocklist.de | Select Typ: {all} {ssh} {mail} {apache} {imap} {ftp} {sip} {bots} {strongips} {ircbot} {bruteforcelogin} 
BLOCKLIST_TYP="all" 

# Delete IP after x Day's OR use 0 for permanent block 
DELETE_IP_AFTER="7"  

# Loglevel 1: Show Stats at the bottom / Loglevel 2: Show all / Loglevel 0: disable
LOGLEVEL=1

############################################################################################################### 
# Do NOT change after here 
############################################################################################################### 

# CREATE TABLE AutoBlockIP(IP varchar(50) PRIMARY KEY,RecordTime date NOT NULL,ExpireTime date NOT NULL,Deny boolean NOT NULL,IPStd varchr(50) NOT NULL,Type INTEGER,Meta varchar(256))
countadded=0
countskipped=0
UNIXTIME=$(date +%s)
UNIXTIME_DELETE_IP=$(date -d "+$DELETE_IP_AFTER days" +%s) 
wget -q "https://lists.blocklist.de/lists/$BLOCKLIST_TYP.txt" -O /tmp/blocklist.txt 
IPcountList=$(cat "/tmp/blocklist.txt" | grep -Eo "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" | wc -l)

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
                INSERT=$(sqlite3 /etc/synoautoblock.db "INSERT INTO AutoBlockIP VALUES ('$BLOCKED_IP','$UNIXTIME','$UNIXTIME_DELETE_IP','1','$IPv6','$TYPE','$META')")
                countadded=$(( $countadded + 1 ))
                if [[ $LOGLEVEL -eq 2 ]]; then 
                    echo "IP added to Database!    -->  $BLOCKED_IP" 
                elif [[ $LOGLEVEL -eq 1 ]]; then
                    echo -n "."
                fi
            else 
                countskipped=$(( $countskipped + 1 ))
                if [[ $LOGLEVEL -eq 2 ]]; then
                    echo "IP already in Database!  -->  $BLOCKED_IP" 
                elif [[ $LOGLEVEL -eq 1 ]]; then
                    echo -n "."
                fi
            fi 
        fi 
    done < /tmp/blocklist.txt

rm /tmp/blocklist.txt 

if [[ $LOGLEVEL -eq 1 ]] || [[ $LOGLEVEL -eq 2 ]]; then 
    END=$(date +%s) 
    RUNTIME=$((END-UNIXTIME)) 
    echo -e
    echo "duration of the process:      $RUNTIME Seconds" 
    echo "count of IPs in list:         $IPcountList"
    echo "added IPs:                    $countadded"
    echo "skipped IPs:                  $countskipped"
    echo "count of blocked IPs:         $(sqlite3 /etc/synoautoblock.db "SELECT count(IP) FROM AutoBlockIP WHERE TYPE='0' " )"
fi

exit 0 