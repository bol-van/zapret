. "$EXEDIR/../config"

TMPDIR=/tmp
ZIPSET=zapret
ZIPSET6=zapret6
ZIPLIST="$EXEDIR/zapret-ip.txt"
ZIPLIST6="$EXEDIR/zapret-ip6.txt"
ZIPLIST_EXCLUDE="$EXEDIR/zapret-ip-exclude.txt"
ZIPLIST_EXCLUDE6="$EXEDIR/zapret-ip-exclude6.txt"
ZIPLIST_USER="$EXEDIR/zapret-ip-user.txt"
ZIPLIST_USER6="$EXEDIR/zapret-ip-user6.txt"
ZUSERLIST="$EXEDIR/zapret-hosts-user.txt"
ZHOSTLIST="$EXEDIR/zapret-hosts.txt"

ZIPSET_IPBAN=ipban
ZIPSET_IPBAN6=ipban6
ZIPLIST_IPBAN="$EXEDIR/zapret-ip-ipban.txt"
ZIPLIST_IPBAN6="$EXEDIR/zapret-ip-ipban6.txt"
ZIPLIST_USER_IPBAN="$EXEDIR/zapret-ip-user-ipban.txt"
ZIPLIST_USER_IPBAN6="$EXEDIR/zapret-ip-user-ipban6.txt"
ZUSERLIST_IPBAN="$EXEDIR/zapret-hosts-user-ipban.txt"

MDIG="$EXEDIR/../mdig/mdig"
[ -z "$MDIG_THREADS" ] && MDIG_THREADS=30

zzexist()
{
 [ -f "$1.gz" ] || [ -f "$1" ]
}
zzcat()
{
 if [ -f "$1.gz" ]; then
 	gunzip -c "$1.gz"
 else
 	cat "$1"
 fi
}
zz()
{
 gzip -c >"$1.gz"
}

digger()
{
 # $1 - hostlist
 # $2 - family (4|6)
 >&2 echo digging $(wc -l <"$1") ipv$2 domains : "$1"

 if [ -x "$MDIG" ]; then
  zzcat "$1" | "$MDIG" --family=$2 --threads=$MDIG_THREADS --stats=1000
 else
  local A=A
  [ "$2" = "6" ] && A=AAAA
  zzcat "$1" | dig $A +short +time=8 +tries=2 -f - | grep -E '^[^;].*[^\.]$'
 fi
}

cut_local()
{
  grep -vE '^192\.168\.|^127\.|^10\.'
}
cut_local6()
{
  grep -vE '^::|fc..:|fd..:'
}


getuser()
{
 [ -f "$ZUSERLIST" ] && {
  [ "$DISABLE_IPV4" != "1" ] && digger "$ZUSERLIST" 4 | cut_local | sort -u > "$ZIPLIST_USER"
  [ "$DISABLE_IPV6" != "1" ] && digger "$ZUSERLIST" 6 | cut_local6 | sort -u > "$ZIPLIST_USER6"
 }
 [ -f "$ZUSERLIST_IPBAN" ] && {
  [ "$DISABLE_IPV4" != "1" ] && digger "$ZUSERLIST_IPBAN" 4 | cut_local | sort -u > "$ZIPLIST_USER_IPBAN"
  [ "$DISABLE_IPV6" != "1" ] && digger "$ZUSERLIST_IPBAN" 6 | cut_local6 | sort -u > "$ZIPLIST_USER_IPBAN6"
 }
}

