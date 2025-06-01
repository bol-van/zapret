#!/bin/sh

if [ $(systemctl is-active zapret) = 'active' ]; then
    echo 'zapret: on'
else
    echo 'zapret: off'
fi
