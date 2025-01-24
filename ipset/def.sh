EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"
ZAPRET_BASE=${ZAPRET_BASE:-"$(cd "$EXEDIR/.."; pwd)"}
ZAPRET_RW=${ZAPRET_RW:-"$ZAPRET_BASE"}
ZAPRET_CONFIG=${ZAPRET_CONFIG:-"$ZAPRET_RW/config"}
IPSET_RW_DIR="$ZAPRET_RW/ipset"

[ -f "$ZAPRET_CONFIG" ] && . "$ZAPRET_CONFIG"
. "$ZAPRET_BASE/common/base.sh"

[ -z "$TMPDIR" ] && TMPDIR=/tmp
[ -z "$GZIP_LISTS" ] && GZIP_LISTS=1

[ -z "$SET_MAXELEM" ] && SET_MAXELEM=262144
[ -z "$IPSET_OPT" ] && IPSET_OPT="hashsize 262144 maxelem $SET_MAXELEM"
[ -z "$SET_MAXELEM_EXCLUDE" ] && SET_MAXELEM_EXCLUDE=65536
[ -z "$IPSET_OPT_EXCLUDE" ] && IPSET_OPT_EXCLUDE="hashsize 1024 maxelem $SET_MAXELEM_EXCLUDE"

[ -z "$IPFW_TABLE_OPT" ] && IPFW_TABLE_OPT="algo addr:radix"
[ -z "$IPFW_TABLE_OPT_EXCLUDE" ] && IPFW_TABLE_OPT_EXCLUDE="algo addr:radix"

ZIPSET=zapret
ZIPSET6=zapret6
ZIPSET_EXCLUDE=nozapret
ZIPSET_EXCLUDE6=nozapret6
ZIPLIST="$IPSET_RW_DIR/zapret-ip.txt"
ZIPLIST6="$IPSET_RW_DIR/zapret-ip6.txt"
ZIPLIST_EXCLUDE="$IPSET_RW_DIR/zapret-ip-exclude.txt"
ZIPLIST_EXCLUDE6="$IPSET_RW_DIR/zapret-ip-exclude6.txt"
ZIPLIST_USER="$IPSET_RW_DIR/zapret-ip-user.txt"
ZIPLIST_USER6="$IPSET_RW_DIR/zapret-ip-user6.txt"
ZUSERLIST="$IPSET_RW_DIR/zapret-hosts-user.txt"
ZHOSTLIST="$IPSET_RW_DIR/zapret-hosts.txt"

ZIPSET_IPBAN=ipban
ZIPSET_IPBAN6=ipban6
ZIPLIST_IPBAN="$IPSET_RW_DIR/zapret-ip-ipban.txt"
ZIPLIST_IPBAN6="$IPSET_RW_DIR/zapret-ip-ipban6.txt"
ZIPLIST_USER_IPBAN="$IPSET_RW_DIR/zapret-ip-user-ipban.txt"
ZIPLIST_USER_IPBAN6="$IPSET_RW_DIR/zapret-ip-user-ipban6.txt"
ZUSERLIST_IPBAN="$IPSET_RW_DIR/zapret-hosts-user-ipban.txt"
ZUSERLIST_EXCLUDE="$IPSET_RW_DIR/zapret-hosts-user-exclude.txt"


[ -n "$IP2NET" ] || IP2NET="$ZAPRET_BASE/ip2net/ip2net"
[ -n "$MDIG" ] || MDIG="$ZAPRET_BASE/mdig/mdig"
[ -z "$MDIG_THREADS" ] && MDIG_THREADS=30



# BSD grep is damn slow with -f option. prefer GNU grep (ggrep) if present
# MacoS in cron does not include /usr/local/bin to PATH
if [ -x /usr/local/bin/ggrep ] ; then
 GREP=/usr/local/bin/ggrep
elif [ -x /usr/local/bin/grep ] ; then
 GREP=/usr/local/bin/grep
elif exists ggrep; then
 GREP=$(whichq ggrep)
else
 GREP=$(whichq grep)
fi

# GNU awk is faster
if exists gawk; then
 AWK=gawk
else
 AWK=awk
fi

grep_supports_b()
{
 # \b does not work with BSD grep
 $GREP --version 2>&1 | $GREP -qE "BusyBox|GNU"
}
get_ip_regex()
{
 REG_IPV4='((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/([0-9]|[12][0-9]|3[012]))?'
 REG_IPV6='[0-9a-fA-F]{1,4}:([0-9a-fA-F]{1,4}|:)+(\/([0-9][0-9]?|1[01][0-9]|12[0-8]))?'
 # good but too slow
 # REG_IPV6='([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}(/[0-9]+)?|([0-9a-fA-F]{1,4}:){1,7}:(/[0-9]+)?|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}(/[0-9]+)?|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}(/[0-9]+)?|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}(/[0-9]+)?|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}(/[0-9]+)?|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}(/[0-9]+)?|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})(/[0-9]+)?|:((:[0-9a-fA-F]{1,4}){1,7}|:)(/([0-9][0-9]?|1[01][0-9]|12[0-8]))?'
# grep_supports_b && {
#  REG_IPV4="\b$REG_IPV4\b"
#  REG_IPV6="\b$REG_IPV6\b"
# }
}

ip2net4()
{
 if [ -x "$IP2NET" ]; then
  "$IP2NET" -4 $IP2NET_OPT4
 else
  sort -u
 fi
}
ip2net6()
{
 if [ -x "$IP2NET" ]; then
  "$IP2NET" -6 $IP2NET_OPT6
 else
  sort -u
 fi
}

zzexist()
{
 [ -f "$1.gz" ] || [ -f "$1" ]
}
zztest()
{
 gzip -t "$1" 2>/dev/null
}
zzcat()
{
 if [ -f "$1.gz" ]; then
 	gunzip -c "$1.gz"
 elif [ -f "$1" ]; then
	if zztest "$1"; then
 		gunzip -c "$1"
	else
	 	cat "$1"
	fi
 fi
}
zz()
{
 if [ "$GZIP_LISTS" = "1" ]; then
  gzip -c >"$1.gz"
  rm -f "$1"
 else
  cat >"$1"
  rm -f "$1.gz"
 fi
}
zzsize()
{
 local f="$1"
 [ -f "$1.gz" ] && f="$1.gz"
 if [ -f "$f" ]; then
  wc -c <"$f" | xargs
 else
  printf 0
 fi
}
zzcopy()
{
 local is_gz=0
 zztest "$1" && is_gz=1
 if [ "$GZIP_LISTS" = 1 -a $is_gz = 1 ]; then
  cp "$1" "${2}.gz"
 elif [ "$GZIP_LISTS" != 1 -a $is_gz != 1 ]; then
  cp "$1" "$2"
 else
  zzcat "$1" | zz "$2"
 fi
}

digger()
{
 # $1 - family (4|6)
 # $2 - s=enable mdig stats
 if [ -x "$MDIG" ]; then
  local cmd
  [ "$2" = "s" ] && cmd=--stats=1000
  "$MDIG" --family=$1 --threads=$MDIG_THREADS $cmd
 else
  local A=A
  [ "$1" = "6" ] && A=AAAA
  dig $A +short +time=8 +tries=2 -f - | $GREP -E '^[^;].*[^\.]$'
 fi
}
filedigger()
{
 # $1 - hostlist
 # $2 - family (4|6)
 >&2 echo digging $(wc -l <"$1" | xargs) ipv$2 domains : "$1"
 zzcat "$1" | digger $2 s
}
flush_dns_cache()
{
 echo clearing all known DNS caches

 if exists killall; then
  killall -HUP dnsmasq 2>/dev/null
  # MacOS
  killall -HUP mDNSResponder 2>/dev/null
 elif exists pkill; then
  pkill -HUP ^dnsmasq$
 else
  echo no mass killer available ! cant flush dnsmasq
 fi
 
 if exists rndc; then
  rndc flush
 fi

 if exists systemd-resolve; then
  systemd-resolve --flush-caches
 fi

}
dnstest()
{
 local ip="$(echo w3.org | digger 46)"
 [ -n "$ip" ]
}
dnstest_with_cache_clear()
{
 flush_dns_cache
 if dnstest ; then
    echo DNS is working
    return 0
 else
    echo "! DNS is not working"
    return 1
 fi
}


cut_local()
{
  $GREP -vE '^192\.168\.|^127\.|^10\.'
}
cut_local6()
{
  $GREP -vE '^::|^fc..:|^fd..:|^fe8.:|^fe9.:|^fea.:|^feb.:|^FC..:|^FD..:|^FE8.:|^FE9.:|^FEA.:|^FEB.:'
}

oom_adjust_high()
{
	[ -f /proc/$$/oom_score_adj ] && {
		echo setting high oom kill priority
		echo -n 100 >/proc/$$/oom_score_adj
	}
}

getexclude()
{
 oom_adjust_high
 dnstest_with_cache_clear || return
 [ -f "$ZUSERLIST_EXCLUDE" ] && {
  [ "$DISABLE_IPV4" != "1" ] && filedigger "$ZUSERLIST_EXCLUDE" 4 | sort -u > "$ZIPLIST_EXCLUDE"
  [ "$DISABLE_IPV6" != "1" ] && filedigger "$ZUSERLIST_EXCLUDE" 6 | sort -u > "$ZIPLIST_EXCLUDE6"
 }
 return 0
}

_get_ipban()
{
 [ -f "$ZUSERLIST_IPBAN" ] && {
  [ "$DISABLE_IPV4" != "1" ] && filedigger "$ZUSERLIST_IPBAN" 4 | cut_local | sort -u > "$ZIPLIST_USER_IPBAN"
  [ "$DISABLE_IPV6" != "1" ] && filedigger "$ZUSERLIST_IPBAN" 6 | cut_local6 | sort -u > "$ZIPLIST_USER_IPBAN6"
 }
}
getuser()
{
 getexclude || return
 [ -f "$ZUSERLIST" ] && {
  [ "$DISABLE_IPV4" != "1" ] && filedigger "$ZUSERLIST" 4 | cut_local | sort -u > "$ZIPLIST_USER"
  [ "$DISABLE_IPV6" != "1" ] && filedigger "$ZUSERLIST" 6 | cut_local6 | sort -u > "$ZIPLIST_USER6"
 }
 _get_ipban
 return 0
}
getipban()
{
 getexclude || return
 _get_ipban
 return 0
}

hup_zapret_daemons()
{
 echo forcing zapret daemons to reload their hostlist
 if exists killall; then
  killall -HUP tpws nfqws dvtws 2>/dev/null
 elif exists pkill; then
  pkill -HUP ^tpws$ ^nfqws$ ^dvtws$
 else
  echo no mass killer available ! cant HUP zapret daemons
 fi
}
