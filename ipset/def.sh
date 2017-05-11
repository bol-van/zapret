TMPDIR=/tmp
ZIPSET=zapret
ZIPLIST=$EXEDIR/zapret-ip.txt
ZIPLIST_EXCLUDE=$EXEDIR/zapret-ip-exclude.txt
ZIPLIST_USER=$EXEDIR/zapret-ip-user.txt
ZUSERLIST=$EXEDIR/zapret-hosts-user.txt

ZIPSET_IPBAN=ipban
ZIPLIST_IPBAN=$EXEDIR/zapret-ip-ipban.txt
ZIPLIST_USER_IPBAN=$EXEDIR/zapret-ip-user-ipban.txt
ZUSERLIST_IPBAN=$EXEDIR/zapret-hosts-user-ipban.txt

getuser()
{
 [ -f $ZUSERLIST ] && {
  dig A +short +time=8 +tries=2 -f $ZUSERLIST | grep -E '^[^;].*[^.]$' | grep -vE '^192\.168\.[0-9]+.[0-9]+$' | grep -vE '^127\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -vE '^10\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u >$ZIPLIST_USER
 }
 [ -f $ZUSERLIST_IPBAN ] && {
  dig A +short +time=8 +tries=2 -f $ZUSERLIST_IPBAN | grep -E '^[^;].*[^.]$' | grep -vE '^192\.168\.[0-9]+\.[0-9]+$' | grep -vE '^127\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -vE '^10\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u >$ZIPLIST_USER_IPBAN
 }
}

cut_local()
{
  grep -vE '^192\.168\.[0-9]+\.[0-9]+$' |
  grep -vE '^127\.[0-9]+\.[0-9]+\.[0-9]+$' |
  grep -vE '^10\.[0-9]+\.[0-9]+\.[0-9]+$'
}
