#!/bin/sh

SCRIPT=$(readlink -f "$0")
EXEDIR=$(dirname "$SCRIPT")

. "$EXEDIR/def.sh"

getuser

. "$EXEDIR/antifilter.helper"

get_antifilter https://antifilter.network/download/ipsum.lst "$ZIPLIST"

"$EXEDIR/create_ipset.sh"
