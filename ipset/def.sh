TMPDIR=/tmp
ZIPSET=zapret
ZIPLIST=$EXEDIR/zapret-ip.txt
ZIPLIST_EXCLUDE=$EXEDIR/zapret-ip-exclude.txt
ZIPLIST_USER=$EXEDIR/zapret-ip-user.txt
ZUSERLIST=$EXEDIR/zapret-hosts-user.txt
ZHOSTLIST=$EXEDIR/zapret-hosts.txt

ZIPSET_IPBAN=ipban
ZIPLIST_IPBAN=$EXEDIR/zapret-ip-ipban.txt
ZIPLIST_USER_IPBAN=$EXEDIR/zapret-ip-user-ipban.txt
ZUSERLIST_IPBAN=$EXEDIR/zapret-hosts-user-ipban.txt

MDIG=$EXEDIR/../mdig/mdig
MDIG_THREADS=30

digger()
{
 if [ -x $MDIG ]; then
  $MDIG --family=4 --threads=$MDIG_THREADS <$1
 else
  dig A +short +time=8 +tries=2 -f $1 | grep -E '^[^;].*[^\.]$'
 fi
}

cut_local()
{
  grep -vE '^192\.168\.[0-9]+\.[0-9]+$' |
  grep -vE '^127\.[0-9]+\.[0-9]+\.[0-9]+$' |
  grep -vE '^10\.[0-9]+\.[0-9]+\.[0-9]+$'
}

getuser()
{
 [ -f $ZUSERLIST ] && {
  digger $ZUSERLIST | cut_local | sort -u >$ZIPLIST_USER
 }
 [ -f $ZUSERLIST_IPBAN ] && {
  digger $ZUSERLIST_IPBAN | cut_local | sort -u >$ZIPLIST_USER_IPBAN
 }
}
