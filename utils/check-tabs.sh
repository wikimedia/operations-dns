#!/bin/sh

if ! grep -q operations/dns .gitreview 2>/dev/null; then
    echo "ERROR: must be executed from the DNS repo root"
    exit 2
fi

(git --no-pager grep -P '\t') && HAS_TAB=1 || HAS_TAB=0
if [ $HAS_TAB -eq 1 ]; then
    echo "ERROR: Tabs found"
else
    echo "OK: No tabs"
fi
exit $HAS_TAB
