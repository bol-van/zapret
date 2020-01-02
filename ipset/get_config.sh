#!/bin/sh
# run script specified in config

SCRIPT=$(readlink -f "$0")
EXEDIR=$(dirname "$SCRIPT")

. "$EXEDIR/../config"

[ -z "$GETLIST" ] && GETLIST=get_exclude.sh
[ -x "$EXEDIR/$GETLIST" ] && exec "$EXEDIR/$GETLIST"
