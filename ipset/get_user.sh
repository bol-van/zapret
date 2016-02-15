#!/bin/sh
# resolve user host list

SCRIPT=$(readlink -f $0)
EXEDIR=$(dirname $SCRIPT)

. "$EXEDIR/def.sh"

[ -f $ZUSERLIST ] && {
 dig A +short +time=8 +tries=2 -f $ZUSERLIST | grep -E '^[^;].*[^.]$' | grep -vE '^192.168.[0-9]*.[0-9]*$' | grep -vE '^127.[0-9]*.[0-9]*.[0-9]*$' | grep -vE '^10.[0-9]*.[0-9]*.[0-9]*$' | sort | uniq >$ZIPLIST_USER
}
