#!/bin/sh
# create ipset from resolved ip's

SCRIPT=$(readlink -f $0)
EXEDIR=$(dirname $SCRIPT)

. "$EXEDIR/def.sh"

create_ipset()
{
ipset flush $1 2>/dev/null || ipset create $1 hash:ip maxelem 262144
for f in "$2" "$3"
do
 [ -f "$f" ] && {
  echo Adding to ipset $1 : $f
  if [ -f "$ZIPLIST_EXCLUDE" ] ; then
   grep -vxFf $ZIPLIST_EXCLUDE "$f" | sort -u | while read ip; do echo add $1 $ip; done | ipset -! restore
  else
   sort -u "$f" | while read ip; do echo add $1 $ip; done | ipset -! restore
  fi
 }
done
return 0
}

create_ipset $ZIPSET $ZIPLIST $ZIPLIST_USER
create_ipset $ZIPSET_IPBAN $ZIPLIST_IPBAN $ZIPLIST_USER_IPBAN
