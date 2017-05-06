#!/bin/sh
# get rublacklist and resolve it

SCRIPT=$(readlink -f $0)
EXEDIR=$(dirname $SCRIPT)

. "$EXEDIR/def.sh"

ZREESTR=/tmp/reestr.txt
ZANTIZAPRET=/tmp/antizapret.txt
ZURL_REESTR=http://reestr.rublacklist.net/api/current
ZURL_ANTIZAPRET=http://antizapret.prostovpn.org/iplist.txt

getuser

curl --fail --max-time 300 --max-filesize 41943040 "$ZURL_REESTR" |
  grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |
  grep -vE '^192\.168\.[0-9]+\.[0-9]+$' |
  grep -vE '^127\.[0-9]+\.[0-9]+\.[0-9]+$' |
  grep -vE '^10\.[0-9]+\.[0-9]+\.[0-9]+$' |
  sort -u >$ZREESTR
dlsize=$(wc -c "$ZREESTR" | cut -f 1 -d ' ')
if test $dlsize -lt 10240; then
 echo reestr ip list is too small. can be bad.
 exit 2
fi
curl --fail --max-time 300 --max-filesize 33554432 -k -L "$ZURL_ANTIZAPRET" |
 grep -vE '^192\.168\.[0-9]+\.[0-9]+$' |
 grep -vE '^127\.[0-9]+\.[0-9]+\.[0-9]+$' |
 grep -vE '^10\.[0-9]+\.[0-9]+\.[0-9]+$' >$ZANTIZAPRET
dlsize=$(wc -c "$ZANTIZAPRET" | cut -f 1 -d ' ')
if test $dlsize -lt 10240; then
 echo antizapret ip list is too small. can be bad.
 exit 2
fi

grep -vFf $ZREESTR $ZANTIZAPRET >$ZIPLIST
mv -f $ZREESTR $ZIPLIST_IPBAN
rm -f $ZANTIZAPRET 

"$EXEDIR/create_ipset.sh"
