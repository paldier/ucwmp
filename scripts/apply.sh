#!/bin/sh
exec >>/tmp/log.txt
exec 2>&1

path="$1"
type="$2"
file="$3"

echo "Apply file $file (type='$type', path='$path')"
