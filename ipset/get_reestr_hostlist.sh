#!/bin/sh

SCRIPT=$(readlink -f "$0")
EXEDIR=$(dirname "$SCRIPT")

. "$EXEDIR/def.sh"

# useful in case ipban set is used in custom scripts
getuser
"$EXEDIR/create_ipset.sh"

ZREESTR="$TMPDIR/zapret.txt"
#ZURL=https://reestr.rublacklist.net/api/current
ZURL=https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv

curl -k --fail --max-time 150 --connect-timeout 5 --retry 3 --max-filesize 251658240 "$ZURL" >"$ZREESTR" ||
{
 echo reestr list download failed   
 exit 2
}
dlsize=$(wc -c "$ZREESTR" | cut -f 1 -d ' ')
if test $dlsize -lt 204800; then
 echo list file is too small. can be bad.
 exit 2
fi
(cut -s -f2 -d';' "$ZREESTR" | grep -a . | sed -re 's/^\*\.(.+)$/\1/' | awk '{ print tolower($0) }' ; cat "$ZUSERLIST" ) | sort -u | zz "$ZHOSTLIST"
rm -f "$ZREESTR"

# force daemons to reload hostlist if they are running
killall -HUP tpws 2>/dev/null
killall -HUP nfqws 2>/dev/null

exit 0
