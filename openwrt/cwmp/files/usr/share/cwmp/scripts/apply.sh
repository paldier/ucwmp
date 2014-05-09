#!/bin/sh

path="$1"
type="$2"
file="$3"
url="$4"

case "$type" in
	'1 Firmware Upgrade Image')
		sysupgrade "$path"
	;;
esac
