#!/bin/sh
# create ipset from resolved ip's

SCRIPT=$(readlink -f $0)
EXEDIR=$(dirname $SCRIPT)

. "$EXEDIR/def.sh"

create_ipset()
{
ipset flush $2 2>/dev/null || ipset create $2 $1 maxelem 524288
for f in "$3" "$4"
do
 [ -f "$f" ] && {
  echo Adding to ipset $2 \($1\) : $f
  if [ -f "$ZIPLIST_EXCLUDE" ] ; then
   grep -vxFf $ZIPLIST_EXCLUDE "$f" | sort -u | sed -nre "s/^.+$/add $2 &/p" | ipset -! restore
  else
   sort -u "$f" | sed -nre "s/^.+$/add $2 &/p" | ipset -! restore
  fi
 }
done
return 0
}

create_ipset hash:net $ZIPSET $ZIPLIST $ZIPLIST_USER
create_ipset hash:net $ZIPSET_IPBAN $ZIPLIST_IPBAN $ZIPLIST_USER_IPBAN
