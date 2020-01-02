#!/bin/sh
# create ipset from resolved ip's
# $1=no-update    - do not update ipset, only create if its absent

SCRIPT=$(readlink -f "$0")
EXEDIR=$(dirname "$SCRIPT")

[ -z "$IPSET_OPT" ] && IPSET_OPT="hashsize 262144 maxelem 2097152"
[ -z "$IPSET_OPT_EXCLUDE" ] && IPSET_OPT_EXCLUDE="hashsize 1024 maxelem 65536"

IP2NET="$EXEDIR/../ip2net/ip2net"

. "$EXEDIR/def.sh"
IPSET_CMD="$TMPDIR/ipset_cmd.txt"
IPSET_SAVERAM_CHUNK_SIZE=20000
IPSET_SAVERAM_MIN_FILESIZE=131072


while [ -n "$1" ]; do
	[ "$1" = "no-update" ] && NO_UPDATE=1
	shift
done


file_extract_lines()
{
 # $1 - filename
 # $2 - from line (starting with 0)
 # $3 - line count
 # awk "{ err=1 } NR < $(($2+1)) { next } { print; err=0 } NR == $(($2+$3)) { exit err } END {exit err}" "$1"
 awk "NR < $(($2+1)) { next } { print } NR == $(($2+$3)) { exit }" "$1"
}
ipset_restore_chunked()
{
 # $1 - filename
 # $2 - chunk size
 local pos lines
 [ -f "$1" ] || return
 lines=$(wc -l <"$1")
 pos=$lines
 while [ "$pos" -gt "0" ]; do
    pos=$((pos-$2))
    [ "$pos" -lt "0" ] && pos=0
    file_extract_lines "$1" $pos $2 | ipset -! restore
    sed -i "$(($pos+1)),$ d" "$1"
 done
}


sortu()
{
 sort -u
}
ip2net4()
{
 "$IP2NET" -4 $IP2NET_OPT4
}
ip2net6()
{
 "$IP2NET" -6 $IP2NET_OPT6
}
ipset_get_script()
{
 # $1 - filename
 # $2 - ipset name
 # $3 - "6" = ipv6
 local filter=sortu
 [ -x "$IP2NET" ] && filter=ip2net$3
 zzcat "$1" | $filter | sed -nre "s/^.+$/add $2 &/p"
}

ipset_restore()
{
 # $1 - filename
 # $2 - ipset name
 # $3 - "6" = ipv6
 zzexist "$1" || return
 local fsize=$(zzsize "$1")
 local svram=0
 # do not saveram small files. file can also be gzipped
 [ "$SAVERAM" = "1" ] && [ "$fsize" -ge "$IPSET_SAVERAM_MIN_FILESIZE" ] && svram=1

 local T="Adding to ipset $2 ($IPSTYPE"
 [ -x "$IP2NET" ] && T="$T, ip2net"
 [ "$svram" = "1" ] && T="$T, saveram"
 T="$T) : $f"
 echo $T

 if [ "$svram" = "1" ]; then
  ipset_get_script "$1" "$2" "$3" >"$IPSET_CMD"
  ipset_restore_chunked "$IPSET_CMD" $IPSET_SAVERAM_CHUNK_SIZE
  rm -f "$IPSET_CMD"
 else
  ipset_get_script "$1" "$2" "$3" | ipset -! restore
 fi
}

create_ipset()
{
 local IPSTYPE
 if [ -x "$IP2NET" ]; then
  IPSTYPE=hash:net
 else
  IPSTYPE=$3
 fi
 if [ "$1" -eq "6" ]; then
  FAMILY=inet6
 else
  FAMILY=inet
 fi
 ipset create $2 $IPSTYPE $4 family $FAMILY 2>/dev/null || {
  [ "$NO_UPDATE" = "1" ] && return
 }
 ipset flush $2
 for f in "$5" "$6" ; do
  ipset_restore "$f" "$2" $1
 done
 return 0
}

oom_adjust_high

# ipset seem to buffer the whole script to memory
# on low RAM system this can cause oom errors
# in SAVERAM mode we feed script lines in portions starting from the end, while truncating source file to free /tmp space
# only /tmp is considered tmpfs. other locations mean tmpdir was redirected to a disk
SAVERAM=0
[ "$TMPDIR" = "/tmp" ] && {
 RAMSIZE=$(grep MemTotal /proc/meminfo | awk '{print $2}')
 [ "$RAMSIZE" -lt "110000" ] && SAVERAM=1
}
 
[ "$DISABLE_IPV4" != "1" ] && {
  create_ipset 4 $ZIPSET hash:ip "$IPSET_OPT" "$ZIPLIST" "$ZIPLIST_USER"
  create_ipset 4 $ZIPSET_IPBAN hash:ip "$IPSET_OPT" "$ZIPLIST_IPBAN" "$ZIPLIST_USER_IPBAN"
  create_ipset 4 $ZIPSET_EXCLUDE hash:net "$IPSET_OPT_EXCLUDE" "$ZIPLIST_EXCLUDE"
}

[ "$DISABLE_IPV6" != "1" ] && {
  create_ipset 6 $ZIPSET6 hash:ip "$IPSET_OPT" "$ZIPLIST6" "$ZIPLIST_USER6"
  create_ipset 6 $ZIPSET_IPBAN6 hash:ip "$IPSET_OPT" "$ZIPLIST_IPBAN6" "$ZIPLIST_USER_IPBAN6"
  create_ipset 6 $ZIPSET_EXCLUDE6 hash:net "$IPSET_OPT_EXCLUDE" "$ZIPLIST_EXCLUDE6"
}

true
