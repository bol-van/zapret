#!/bin/sh
# run script specified in config

IPSET_DIR="$(dirname "$0")"
IPSET_DIR="$(cd "$IPSET_DIR"; pwd)"

[ -f "$IPSET_DIR/../config" ] && . "$IPSET_DIR/../config"

[ -z "$GETLIST" ] && GETLIST=get_ipban.sh
[ -x "$IPSET_DIR/$GETLIST" ] && exec "$IPSET_DIR/$GETLIST"
