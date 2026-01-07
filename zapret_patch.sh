#!/bin/sh
[ -e "/tmp/zapret_patch.log" ] && return 0

/data/zapret/install_easy.sh

echo "zapret reinstalled" > /tmp/zapret_patch.log 
