#!/bin/sh
# create ipset from resolved ip's

SCRIPT=$(readlink -f $0)
EXEDIR=$(dirname $SCRIPT)

. "$EXEDIR/def.sh"

TEMPIPSET=/tmp/ipset.$ZIPSET.tmp

ipset flush $ZIPSET || ipset create $ZIPSET hash:ip

for f in "$ZIPLIST" "$ZIPLIST_USER"
do
 [ -f $TEMPIPSET ] && rm -f $TEMPIPSET
 [ -n "$f" ] && {
  echo Adding $f
  sort $f | uniq | while read ip;
  do
   echo add $ZIPSET $ip >>$TEMPIPSET
  done
  ipset -! restore <$TEMPIPSET 2>&1
  rm -f $TEMPIPSET
 }
done
