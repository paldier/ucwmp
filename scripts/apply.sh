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
json_add_string url "$url"
ubus call cwmp download_done "$(json_dump)"