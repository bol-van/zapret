#!/bin/sh
# resolve user host list

SCRIPT=$(readlink -f "$0")
EXEDIR=$(dirname "$SCRIPT")

. "$EXEDIR/def.sh"

getuser

"$EXEDIR/create_ipset.sh"
