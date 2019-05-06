#!/bin/sh
# run script specified in config

SCRIPT=$(readlink -f $0)
EXEDIR=$(dirname $SCRIPT)

. "$EXEDIR/../config"

[ -z "$GETLIST" ] && return
[ -x "$EXEDIR/$GETLIST" ] && "$EXEDIR/$GETLIST"
