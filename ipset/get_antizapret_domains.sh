#!/bin/sh

IPSET_DIR="$(dirname "$0")"
IPSET_DIR="$(cd "$IPSET_DIR"; pwd)"

. "$IPSET_DIR/def.sh"

# useful in case ipban set is used in custom scripts
FAIL=
getuser || FAIL=1
"$IPSET_DIR/create_ipset.sh"
[ -n "$FAIL" ] && exit

ZURL=https://antizapret.prostovpn.org/domains-export.txt
ZDOM="$TMPDIR/zapret.txt"


curl -k --fail --max-time 600 --connect-timeout 5 --retry 3 --max-filesize 251658240 "$ZURL" >"$ZDOM" ||
{
 echo domain list download failed   
 exit 2
}

composite_list()
{
 # combine reestr and user list
 if [ -f "$ZUSERLIST_EXCLUDE" ]; then
	nice -n 5 $GREP -xvFf "$ZUSERLIST_EXCLUDE" "$ZDOM"
 else
	cat "$ZDOM"
 fi
 [ -f "$ZUSERLIST" ] && $AWK '{ print tolower($0) }' <"$ZUSERLIST"
}

dlsize=$(LANG=C wc -c "$ZDOM" | xargs | cut -f 1 -d ' ')
if test $dlsize -lt 102400; then
 echo list file is too small. can be bad.
 exit 2
fi

composite_list | sort -u | zz "$ZHOSTLIST"

rm -f "$ZDOM"

hup_zapret_daemons

exit 0
