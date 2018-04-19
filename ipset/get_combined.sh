#!/bin/sh
# get rublacklist and resolve it

SCRIPT=$(readlink -f $0)
EXEDIR=$(dirname $SCRIPT)

. "$EXEDIR/def.sh"

ZREESTR=$TMPDIR/reestr.txt
#ZURL_REESTR=https://reestr.rublacklist.net/api/current
ZURL_REESTR=https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv
ZAZ=$TMPDIR/zapret-ip.txt
ZURL_AZ=http://antizapret.prostovpn.org/iplist.txt

getuser

# assume all https banned by ip
curl -k --fail --max-time 300 --max-filesize 41943040 "$ZURL_REESTR" -o $ZREESTR ||
{
 echo reestr list download failed
 exit 2
}
dlsize=$(wc -c "$ZREESTR" | cut -f 1 -d ' ')
if test $dlsize -lt 1048576; then
 echo reestr ip list is too small. can be bad.
 exit 2
fi
#sed -i 's/\\n/\r\n/g' $ZREESTR
# find entries with https or without domain name - they should be banned by IP
(grep -a "https://" $ZREESTR ; grep -avE "^.*;[^;:/]+\.[^;:/]+;" $ZREESTR ) |
 grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]+)?' |
 cut_local |
 sort -u >$ZIPLIST_IPBAN
 
rm -f $ZREESTR

curl --fail --max-time 120 --max-filesize 10485760 -k -L "$ZURL_AZ" | cut_local >$ZAZ ||
{
 echo antizapret list download failed
 exit 2
}
dlsize=$(wc -c "$ZAZ" | cut -f 1 -d ' ')
if test $dlsize -lt 204800; then
 echo antizapret list file is too small. can be bad.
 exit 2
fi
# do not include hosts banned by ip
grep -xvFf $ZIPLIST_IPBAN $ZAZ >$ZIPLIST
rm -f $ZAZ
"$EXEDIR/create_ipset.sh"
