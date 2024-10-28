#!/bin/sh

# create ipset or ipfw table from resolved ip's
# $1=no-update    - do not update ipset, only create if its absent
# $1=clear        - clear ipset

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"

. "$EXEDIR/def.sh"
. "$ZAPRET_BASE/common/fwtype.sh"
. "$ZAPRET_BASE/common/nft.sh"

IPSET_CMD="$TMPDIR/ipset_cmd.txt"
IPSET_SAVERAM_CHUNK_SIZE=20000
IPSET_SAVERAM_MIN_FILESIZE=131072

NFSET_TEMP="$TMPDIR/nfset_temp.txt"
NFSET_SAVERAM_MIN_FILESIZE=16384
NFSET_SAVERAM_CHUNK_SIZE=1000

IPSET_HOOK_TEMP="$TMPDIR/ipset_hook.txt"

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
	# $1 - ipset name
	sed -nEe "s/^.+$/add $1 &/p"
}
ipset_get_script_from_file()
{
	# $1 - filename
	# $2 - ipset name
	zzcat "$1" | sort -u | ipset_get_script $2
}
ipset_restore()
{
	# $1 - ipset name
	# $2 - filename

	zzexist "$2" || return
	local fsize=$(zzsize "$2")
	local svram=0
	# do not saveram small files. file can also be gzipped
	[ "$SAVERAM" = "1" ] && [ "$fsize" -ge "$IPSET_SAVERAM_MIN_FILESIZE" ] && svram=1

	local T="Adding to ipset $1 "
	[ "$svram" = "1" ] && T="$T (saveram)"
	T="$T : $f"
	echo $T

	if [ "$svram" = "1" ]; then
		ipset_get_script_from_file "$2" "$1" >"$IPSET_CMD"
		ipset_restore_chunked "$IPSET_CMD" $IPSET_SAVERAM_CHUNK_SIZE
		rm -f "$IPSET_CMD"
	else
		ipset_get_script_from_file "$2" "$1" | ipset -! restore
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
		[ "$NO_UPDATE" = "1" ] && return 0
	}
	ipset flush $2
	[ "$DO_CLEAR" = "1" ] || {
		for f in "$5" "$6" ; do
			ipset_restore "$2" "$f"
		done
		[ -n "$IPSET_HOOK" ] && $IPSET_HOOK $2 | ipset_get_script $2 | ipset -! restore
	}
	return 0
}

nfset_get_script_multi()
{
	# $1 - set name
	# $2,$3,... - filenames

	# all in one shot. this allows to merge overlapping ranges
	# good but eats lots of RAM

	local set=$1 nonempty N=1 f
	
	shift
	# first we need to make sure at least one element exists or nft will fail
	while :
	do
		eval f=\$$N
		[ -n "$f" ] || break
		nonempty=$(zzexist "$f" && zzcat "$f" 2>/dev/null | head -n 1)
		[ -n "$nonempty" ] && break
		N=$(($N+1))
	done

	[ -n "$nonempty" ] && {
		echo "add element inet $ZAPRET_NFT_TABLE $set {"
		while [ -n "$1" ]; do
			zzexist "$1" && zzcat "$1" | sed -nEe "s/^.+$/&,/p"
			shift
		done
		echo "}"
	}
}
nfset_restore()
{
	# $1 - set name
	# $2,$3,... - filenames

	echo "Adding to nfset $1 : $2 $3 $4 $5"
	local hookfile
	[ -n "$IPSET_HOOK" ] && {
		$IPSET_HOOK $1 >"$IPSET_HOOK_TEMP"
		[ -s "$IPSET_HOOK_TEMP" ] && hookfile=$IPSET_HOOK_TEMP
	}
	nfset_get_script_multi "$@" $hookfile | nft -f -
	rm -f "$IPSET_HOOK_TEMP"
}
create_nfset()
{
	# $1 - family
	# $2 - set name
	# $3 - maxelem
	# $4,$5 - list files

	local policy
	[ $SAVERAM = "1" ] && policy="policy memory;"
	nft_create_set $2 "type ipv${1}_addr; size $3; flags interval; auto-merge; $policy" || {
		[ "$NO_UPDATE" = "1" ] && return 0
		nft flush set inet $ZAPRET_NFT_TABLE $2
	}
	[ "$DO_CLEAR" = "1" ] || {
		nfset_restore $2 $4 $5
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
		[ "$NO_UPDATE" = "1" ] && return 0
	}
	ipfw -q table $1 flush
	shift
	shift
	[ "$DO_CLEAR" = "1" ] || {
		while [ -n "$1" ]; do
			echo "Adding to ipfw table $name : $1"
			populate_ipfw_table $name "$1"
			shift
		done
		[ -n "$IPSET_HOOK" ] && $IPSET_HOOK $name | add_ipfw_table $name
	}
	return 0
}

print_reloading_backend()
{
	# $1 - backend name
	local s="reloading $1 backend"
	if [ "$NO_UPDATE" = 1 ]; then
		s="$s (no-update)"
	elif [ "$DO_CLEAR" = 1 ]; then
		s="$s (clear)"
	else
		s="$s (forced-update)"
	fi
	echo $s
}


oom_adjust_high
get_fwtype

if [ -n "$LISTS_RELOAD" ] ; then
	if [ "$LISTS_RELOAD" = "-" ] ; then
		echo not reloading ip list backend
		true
	else
		echo executing custom ip list reload command : $LISTS_RELOAD
		$LISTS_RELOAD
		[ -n "$IPSET_HOOK" ] && $IPSET_HOOK
	fi
else
	case "$FWTYPE" in
		iptables)
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
			;;
		nftables)
			nft_create_table && {
				SAVERAM=0
				RAMSIZE=$($GREP MemTotal /proc/meminfo | $AWK '{print $2}')
				[ "$RAMSIZE" -lt "420000" ] && SAVERAM=1
				print_reloading_backend "nftables set"
				[ "$DISABLE_IPV4" != "1" ] && {
					create_nfset 4 $ZIPSET $SET_MAXELEM "$ZIPLIST" "$ZIPLIST_USER"
					create_nfset 4 $ZIPSET_IPBAN $SET_MAXELEM "$ZIPLIST_IPBAN" "$ZIPLIST_USER_IPBAN"
					create_nfset 4 $ZIPSET_EXCLUDE $SET_MAXELEM_EXCLUDE "$ZIPLIST_EXCLUDE"
				}
				[ "$DISABLE_IPV6" != "1" ] && {
					create_nfset 6 $ZIPSET6 $SET_MAXELEM "$ZIPLIST6" "$ZIPLIST_USER6"
					create_nfset 6 $ZIPSET_IPBAN6 $SET_MAXELEM "$ZIPLIST_IPBAN6" "$ZIPLIST_USER_IPBAN6"
					create_nfset 6 $ZIPSET_EXCLUDE6 $SET_MAXELEM_EXCLUDE "$ZIPLIST_EXCLUDE6"
				}
				true
			}
			;;
		ipfw)
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
			;;
		*)
			echo no supported ip list backend found
			true
			;;
		esac

fi
