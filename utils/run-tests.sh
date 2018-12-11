#!/bin/sh

if [ -n "$1" ]; then
    cd "$1" ||:
fi
if [ ! -e templates/wikimedia.org ]; then
    echo "ERROR: Run this from the repo root or specify the repo root path as the only argument"
    exit 2
fi

echo "== Running all CI tests =="
FAIL=0
FAILSTR=""

run_test() {
    echo "=== Running $* ==="
    if ! "$@"; then
        FAIL=1
        FAILSTR="$FAILSTR $1"
    fi
}

run_test utils/check-tabs.sh
run_test utils/zone_validator.py -e
run_test utils/check-gdnsd.sh

if [ $FAIL -eq 0 ]; then
    echo "== OK: All CI tests successful =="
else
    echo "== ERROR: CI tests failed:$FAILSTR =="
fi
exit $FAIL
