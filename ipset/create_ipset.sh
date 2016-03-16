#!/bin/sh
# create ipset from resolved ip's

SCRIPT=$(readlink -f $0)
EXEDIR=$(dirname $SCRIPT)

. "$EXEDIR/def.sh"


create_ipset()
{
ipset flush $1 2>/dev/null || ipset create $1 hash:ip

local TEMPIPSET=/tmp/ipset.$1.tmp

for f in "$2" "$3"
do
 [ -f $TEMPIPSET ] && rm -f $TEMPIPSET
 [ -f "$f" ] && {
  echo Adding to ipset "$1" : $f
  touch $TEMPIPSET
  sort $f | uniq | while read ip;
  do
   echo add $1 $ip >>$TEMPIPSET
  done
  ipset -! restore <$TEMPIPSET 2>&1
  rm -f $TEMPIPSET
 }
done
}

create_ipset $ZIPSET $ZIPLIST $ZIPLIST_USER
create_ipset $ZIPSET_IPBAN $ZIPLIST_IPBAN $ZIPLIST_USER_IPBAN
