#!/bin/sh
# get rublacklist and resolve it

SCRIPT=$(readlink -f $0)
EXEDIR=$(dirname $SCRIPT)

. "$EXEDIR/def.sh"

ZREESTR=$TMPDIR/reestr.txt
ZURL_REESTR=http://reestr.rublacklist.net/api/current
ZAZ=$TMPDIR/zapret-ip.txt
ZURL_AZ=http://antizapret.prostovpn.org/iplist.txt

getuser

# assume all https banned by ip
curl --fail --max-time 300 --max-filesize 41943040 "$ZURL_REESTR" -o $ZREESTR
dlsize=$(wc -c "$ZREESTR" | cut -f 1 -d ' ')
if test $dlsize -lt 1048576; then
 echo reestr ip list is too small. can be bad.
 exit 2
fi
sed -i 's/\\n/\r\n/g' $ZREESTR
grep "https://" $ZREESTR |
 grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |
 cut_local |
 sort -u >$ZIPLIST_IPBAN

rm -f $ZREESTR

curl --fail --max-time 120 --max-filesize 10485760 -k -L "$ZURL_AZ" | cut_local >$ZAZ &&
{
 dlsize=$(wc -c "$ZAZ" | cut -f 1 -d ' ')
 if test $dlsize -lt 204800; then
  echo antizapret list file is too small. can be bad.
  exit 2
 fi
 # do not include hosts banned by ip
 grep -xvFf $ZIPLIST_IPBAN $ZAZ >$ZIPLIST
 rm -f $ZAZ
 "$EXEDIR/create_ipset.sh"
}
