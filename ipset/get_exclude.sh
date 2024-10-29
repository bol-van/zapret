#!/bin/sh
# resolve user host list

IPSET_DIR="$(dirname "$0")"
IPSET_DIR="$(cd "$IPSET_DIR"; pwd)"

. "$IPSET_DIR/def.sh"

getexclude

"$IPSET_DIR/create_ipset.sh"
