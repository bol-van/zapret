#!/bin/sh
# run script specified in config

SCRIPT=$(readlink -f "$0")
EXEDIR=$(dirname "$SCRIPT")

. "$EXEDIR/../config"

[ -z "$GETLIST" ] && exit 0
[ -x "$EXEDIR/$GETLIST" ] && exec "$EXEDIR/$GETLIST"
