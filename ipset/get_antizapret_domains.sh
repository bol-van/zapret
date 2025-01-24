#!/bin/sh

IPSET_DIR="$(dirname "$0")"
IPSET_DIR="$(cd "$IPSET_DIR"; pwd)"

. "$IPSET_DIR/def.sh"

# useful in case ipban set is used in custom scripts
FAIL=
getipban || FAIL=1
"$IPSET_DIR/create_ipset.sh"
[ -n "$FAIL" ] && exit

ZURL=https://antizapret.prostovpn.org:8443/domains-export.txt
ZDOM="$TMPDIR/zapret.txt"


curl -H "Accept-Encoding: gzip" -k --fail --max-time 600 --connect-timeout 5 --retry 3 --max-filesize 251658240 "$ZURL" | gunzip - >"$ZDOM" ||
{
 echo domain list download failed   
 exit 2
}

dlsize=$(LC_ALL=C LANG=C wc -c "$ZDOM" | xargs | cut -f 1 -d ' ')
if test $dlsize -lt 102400; then
 echo list file is too small. can be bad.
 exit 2
fi

sort -u "$ZDOM" | zz "$ZHOSTLIST"

rm -f "$ZDOM"

hup_zapret_daemons

exit 0
