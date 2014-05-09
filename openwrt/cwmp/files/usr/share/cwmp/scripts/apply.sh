#!/bin/sh
. /usr/share/libubox/jshn.sh

path="$1"
type="$2"
file="$3"
url="$4"

json_init
json_add_array "commands"
json_add_array
json_add_string "" "download_done"
json_add_object
json_add_string url "$url"
json_close_object
json_close_array
json_close_array

json_dump > /etc/cwmp-startup.json

case "$type" in
	'1 Firmware Upgrade Image')
		sysupgrade "$path"
	;;
esac
