#!/bin/sh

echo "Looking for tabulations:"
if [ ! -e templates/wikimedia.org ]; then
    echo "ERROR: Run this from the repo root"
    exit 2
fi
(git grep -P '\t') && HAS_TAB=1 || HAS_TAB=0
if [ $HAS_TAB -eq 1 ]; then
    echo "ERROR: Tabs found"
else
    echo "OK: No tabs"
fi
exit $HAS_TAB
