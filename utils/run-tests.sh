#!/bin/sh

# Usage:
# utils/run_tests.sh [-n] [repodir]
#   -n -> Assume no gdnsd installed, cannot run "gdnsd checkconf" test
#   repodir -> ops/dns repo root directory, if not running from it as PWD

DCARGS=
if [ "x${1}" = "x-n" ]; then
   DCARGS=-n
   shift;
fi

if [ -n "$1" ]; then
    cd "$1" ||:
fi
if ! grep -q operations/dns .gitreview 2>/dev/null; then
    echo "ERROR: must be executed from the DNS repo root or have the repo root as first argument"
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

run_test utils/deploy-check.py $DCARGS

if [ $FAIL -eq 0 ]; then
    echo "== OK: All CI tests successful =="
else
    echo "== ERROR: CI tests failed:$FAILSTR =="
fi
exit $FAIL
