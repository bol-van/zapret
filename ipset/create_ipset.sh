#!/bin/sh

# create ipset or ipfw table from resolved ip's
# $1=no-update    - do not update ipset, only create if its absent

IPSET_DIR="$(dirname "$0")"
IPSET_DIR="$(cd "$IPSET_DIR"; pwd)"

. "$IPSET_DIR/def.sh"

IPSET_CMD="$TMPDIR/ipset_cmd.txt"
IPSET_SAVERAM_CHUNK_SIZE=20000
IPSET_SAVERAM_MIN_FILESIZE=131072


while [ -n "$1" ]; do
	[ "$1" = "no-update" ] && NO_UPDATE=1
	[ "$1" = "clear" ] && DO_CLEAR=1
	shift
done


file_extract_lines()
{
 # $1 - filename
 # $2 - from line (starting with 0)
 # $3 - line count
 # awk "{ err=1 } NR < $(($2+1)) { next } { print; err=0 } NR == $(($2+$3)) { exit err } END {exit err}" "$1"
 $AWK "NR < $(($2+1)) { next } { print } NR == $(($2+$3)) { exit }" "$1"
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


ipset_get_script()
{
 # $1 - filename
 # $2 - ipset name
 zzcat "$1" | sort -u | sed -nEe "s/^.+$/add $2 &/p"
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

 local T="Adding to ipset $2 "
 [ "$svram" = "1" ] && T="$T (saveram)"
 T="$T : $f"
 echo $T

 if [ "$svram" = "1" ]; then
  ipset_get_script "$1" "$2" >"$IPSET_CMD"
  ipset_restore_chunked "$IPSET_CMD" $IPSET_SAVERAM_CHUNK_SIZE
  rm -f "$IPSET_CMD"
 else
  ipset_get_script "$1" "$2" | ipset -! restore
 fi
}

create_ipset()
{
 if [ "$1" -eq "6" ]; then
  FAMILY=inet6
 else
  FAMILY=inet
 fi
 ipset create $2 $3 $4 family $FAMILY 2>/dev/null || {
  [ "$NO_UPDATE" = "1" ] && return
 }
 ipset flush $2
 [ "$DO_CLEAR" = "1" ] || {
  for f in "$5" "$6" ; do
   ipset_restore "$f" "$2" $1
  done
 }
 return 0
}


add_ipfw_table()
{
 # $1 - table name
 sed -nEe "s/^.+$/table $1 add &/p" | ipfw -q /dev/stdin
}
populate_ipfw_table()
{
 # $1 - table name
 # $2 - ip list file
 zzexist "$2" || return
 zzcat "$2" | sort -u | add_ipfw_table $1
}
create_ipfw_table()
{
 # $1 - table name
 # $2 - table options
 # $3,$4, ... - ip list files. can be v4,v6 or mixed

 local name=$1
 ipfw table "$name" create $2 2>/dev/null || {
  [ "$NO_UPDATE" = "1" ] && return
 }
 ipfw -q table $1 flush
 shift
 shift
 [ "$DO_CLEAR" = "1" ] || {
  while [ -n "$1" ]; do
   populate_ipfw_table $name "$1"
   shift
  done
 }
}

print_reloading_backend()
{
 # $1 - backend name
 local s="reloading $1 backend"
 if [ "$NO_UPDATE" = 1 ]; then
  s="$s (no-update)"
 else
  s="$s (forced-update)"
 fi
 echo $s
}


oom_adjust_high

if [ -n "$LISTS_RELOAD" ] ; then
 if [ "$LISTS_RELOAD" = "-" ] ; then
  echo not reloading ip list backend
  true
 else
  echo executing custom ip list reload command : $LISTS_RELOAD
  $LISTS_RELOAD
 fi
elif exists ipset; then
 # ipset seem to buffer the whole script to memory
 # on low RAM system this can cause oom errors
 # in SAVERAM mode we feed script lines in portions starting from the end, while truncating source file to free /tmp space
 # only /tmp is considered tmpfs. other locations mean tmpdir was redirected to a disk
 SAVERAM=0
 [ "$TMPDIR" = "/tmp" ] && {
  RAMSIZE=$($GREP MemTotal /proc/meminfo | $AWK '{print $2}')
  [ "$RAMSIZE" -lt "110000" ] && SAVERAM=1
 }
 print_reloading_backend ipset
 [ "$DISABLE_IPV4" != "1" ] && {
   create_ipset 4 $ZIPSET hash:net "$IPSET_OPT" "$ZIPLIST" "$ZIPLIST_USER"
   create_ipset 4 $ZIPSET_IPBAN hash:net "$IPSET_OPT" "$ZIPLIST_IPBAN" "$ZIPLIST_USER_IPBAN"
   create_ipset 4 $ZIPSET_EXCLUDE hash:net "$IPSET_OPT_EXCLUDE" "$ZIPLIST_EXCLUDE"
 }
 [ "$DISABLE_IPV6" != "1" ] && {
   create_ipset 6 $ZIPSET6 hash:net "$IPSET_OPT" "$ZIPLIST6" "$ZIPLIST_USER6"
   create_ipset 6 $ZIPSET_IPBAN6 hash:net "$IPSET_OPT" "$ZIPLIST_IPBAN6" "$ZIPLIST_USER_IPBAN6"
   create_ipset 6 $ZIPSET_EXCLUDE6 hash:net "$IPSET_OPT_EXCLUDE" "$ZIPLIST_EXCLUDE6"
 }
 true
elif exists ipfw; then
 print_reloading_backend "ipfw table"
 if [ "$DISABLE_IPV4" != "1" ] && [ "$DISABLE_IPV6" != "1" ]; then
  create_ipfw_table $ZIPSET "$IPFW_TABLE_OPT" "$ZIPLIST" "$ZIPLIST_USER" "$ZIPLIST6" "$ZIPLIST_USER6"
  create_ipfw_table $ZIPSET_IPBAN "$IPFW_TABLE_OPT" "$ZIPLIST_IPBAN" "$ZIPLIST_USER_IPBAN" "$ZIPLIST_IPBAN6" "$ZIPLIST_USER_IPBAN6"
  create_ipfw_table $ZIPSET_EXCLUDE "$IPFW_TABLE_OPT_EXCLUDE" "$ZIPLIST_EXCLUDE" "$ZIPLIST_EXCLUDE6"
 elif [ "$DISABLE_IPV4" != "1" ]; then
  create_ipfw_table $ZIPSET "$IPFW_TABLE_OPT" "$ZIPLIST" "$ZIPLIST_USER"
  create_ipfw_table $ZIPSET_IPBAN "$IPFW_TABLE_OPT" "$ZIPLIST_IPBAN" "$ZIPLIST_USER_IPBAN"
  create_ipfw_table $ZIPSET_EXCLUDE "$IPFW_TABLE_OPT_EXCLUDE" "$ZIPLIST_EXCLUDE"
 elif [ "$DISABLE_IPV6" != "1" ]; then
  create_ipfw_table $ZIPSET "$IPFW_TABLE_OPT" "$ZIPLIST6" "$ZIPLIST_USER6"
  create_ipfw_table $ZIPSET_IPBAN "$IPFW_TABLE_OPT" "$ZIPLIST_IPBAN6" "$ZIPLIST_USER_IPBAN6"
  create_ipfw_table $ZIPSET_EXCLUDE "$IPFW_TABLE_OPT_EXCLUDE" "$ZIPLIST_EXCLUDE6"
 else
  create_ipfw_table $ZIPSET "$IPFW_TABLE_OPT"
  create_ipfw_table $ZIPSET_IPBAN "$IPFW_TABLE_OPT"
  create_ipfw_table $ZIPSET_EXCLUDE "$IPFW_TABLE_OPT_EXCLUDE"
 fi
 true
else
 echo no supported ip list backend found
 true
fi
