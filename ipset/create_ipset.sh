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
   if [ -f "$5" ] ; then
    zzcat "$f" | grep -vxFf "$5" | "$IP2NET" | sed -nre "s/^.+$/add $2 &/p" | ipset -! restore
   else
    zzcat "$f" | "$IP2NET" | sed -nre "s/^.+$/add $2 &/p" | ipset -! restore
   fi
  else
   echo Adding to ipset $2 \($IPSTYPE\) : $f
   if [ -f "$5" ] ; then
    zzcat "$f" | grep -vxFf "$5" | sort -u | sed -nre "s/^.+$/add $2 &/p" | ipset -! restore
   else
    zzcat "$f" | sort -u | sed -nre "s/^.+$/add $2 &/p" | ipset -! restore
   fi
  fi
 }
done
return 0
}

create_ipset6()
{
local IPSTYPE=$1
ipset flush $2 2>/dev/null || ipset create $2 $IPSTYPE $IPSET_OPT family inet6
for f in "$3" "$4"
do
 zzexist "$f" && {
   echo Adding to ipset $2 \($IPSTYPE\) : $f
   if [ -f "$5" ] ; then
    zzcat "$f" | grep -vxFf "$5" | sort -u | sed -nre "s/^.+$/add $2 &/p" | ipset -! restore
   else
    zzcat "$f" | sort -u | sed -nre "s/^.+$/add $2 &/p" | ipset -! restore
   fi
 }
done
return 0
}

[ "$DISABLE_IPV4" != "1" ] && {
  create_ipset hash:ip $ZIPSET "$ZIPLIST" "$ZIPLIST_USER" "$ZIPLIST_EXCLUDE"
  create_ipset hash:ip $ZIPSET_IPBAN "$ZIPLIST_IPBAN" "$ZIPLIST_USER_IPBAN" "$ZIPLIST_EXCLUDE"
}

[ "$DISABLE_IPV6" != "1" ] && {
  create_ipset6 hash:ip $ZIPSET6 "$ZIPLIST6" "$ZIPLIST_USER6" "$ZIPLIST_EXCLUDE6"
  create_ipset6 hash:ip $ZIPSET_IPBAN6 "$ZIPLIST_IPBAN6" "$ZIPLIST_USER_IPBAN6" "$ZIPLIST_EXCLUDE6"
}

true
