#!/bin/sh
. /usr/share/libubox/jshn.sh
exec >>/tmp/log.txt
exec 2>&1

path="$1"
type="$2"
file="$3"
url="$4"

echo "Apply file $file (type='$type', path='$path')"

json_init
json_add_array "commands"
json_add_array
json_add_string "" "download_done"
json_add_object
json_add_string url "$url"
json_close_object
json_close_array
json_close_array

json_dump > etc/cwmp-startup.json
