#!/bin/sh
# create ipset from resolved ip's

SCRIPT=$(readlink -f "$0")
EXEDIR=$(dirname "$SCRIPT")
IPSET_OPT="hashsize 131072 maxelem 524288"
IP2NET=$EXEDIR/../ip2net/ip2net

. "$EXEDIR/def.sh"


create_ipset()
{
local IPSTYPE
if [ -x "$IP2NET" ]; then
 IPSTYPE=hash:net
else
 IPSTYPE=$1
fi
ipset flush $2 2>/dev/null || ipset create $2 $IPSTYPE $IPSET_OPT
for f in "$3" "$4"
do
 zzexist "$f" && {
  if [ -x "$IP2NET" ]; then
   echo Adding to ipset $2 \($IPSTYPE , ip2net\) : $f
   if [ -f "$ZIPLIST_EXCLUDE" ] ; then
    zzcat "$f" | grep -vxFf "$ZIPLIST_EXCLUDE" | "$IP2NET" | sed -nre "s/^.+$/add $2 &/p" | ipset -! restore
   else
    zzcat "$f" | "$IP2NET" | sed -nre "s/^.+$/add $2 &/p" | ipset -! restore
   fi
  else
   echo Adding to ipset $2 \($IPSTYPE\) : $f
   if [ -f "$ZIPLIST_EXCLUDE" ] ; then
    zzcat "$f" | grep -vxFf "$ZIPLIST_EXCLUDE" | sort -u | sed -nre "s/^.+$/add $2 &/p" | ipset -! restore
   else
    zzcat "$f" | sort -u | sed -nre "s/^.+$/add $2 &/p" | ipset -! restore
   fi
  fi
 }
done
return 0
}

create_ipset hash:ip $ZIPSET "$ZIPLIST" "$ZIPLIST_USER"
create_ipset hash:ip $ZIPSET_IPBAN "$ZIPLIST_IPBAN" "$ZIPLIST_USER_IPBAN"
