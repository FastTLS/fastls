#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root/tools/fastls-check"
export GOWORK=off
binary=$(mktemp "${TMPDIR:-/tmp}/fastls-check.XXXXXXXX")
trap 'rm -f "$binary"' EXIT HUP INT TERM
go build -o "$binary" .
set +e
"$binary" -root "$root" "$@"
result=$?
exit "$result"
