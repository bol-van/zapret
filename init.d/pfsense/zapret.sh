#!/bin/sh

# this file should be placed to /usr/local/etc/rc.d and chmod 755

# prepare system

kldload ipfw
kldload ipdivert

# for older pfsense versions. newer do not have these sysctls
sysctl net.inet.ip.pfil.outbound=ipfw,pf
sysctl net.inet.ip.pfil.inbound=ipfw,pf
sysctl net.inet6.ip6.pfil.outbound=ipfw,pf
sysctl net.inet6.ip6.pfil.inbound=ipfw,pf

# required for newer pfsense versions (2.6.0 tested) to return ipfw to functional state
pfctl -d ; pfctl -e

# add ipfw rules and start daemon

ipfw delete 100
ipfw add 100 divert 989 tcp from any to any 80,443 out not diverted not sockarg
pkill ^dvtws$
dvtws --daemon --port 989 --dpi-desync=multisplit
