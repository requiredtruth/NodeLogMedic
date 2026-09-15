#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$#" -ne 0 ]; then
    echo "Usage: ./demo.sh" >&2
    exit 2
fi
set +e
"$ROOT/cli.sh" "$ROOT/examples/node.log" --color never
status=$?
set -e
# Finding symptoms is the expected successful result for this bundled fixture.
if [ "$status" -eq 0 ] || [ "$status" -eq 1 ]; then
    exit 0
fi
exit "$status"
