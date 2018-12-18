#!/bin/bash
#
# Shell script to use for linting zone templates & config. It sets up a gdnsd
# etc directory, generates zone files based on the templates using
# authdns-gen-zones and runs gdnsd checkconf.
#
# Written by Faidon Liambotis, Aug 2013

set -e

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

die() { echo >&2 "E: $*"; exit 1; }

cleanup() {
   if [ "$CLEANUP" = "yes" ] && [ -d "$TESTDIR" ]; then
       rm -rf "$TESTDIR"
   fi
}
trap cleanup EXIT

if ! grep -q operations/dns .gitreview 2>/dev/null; then
    die "must be executed from the DNS repo root"
fi

TESTDIR=$1
if [ -z "$TESTDIR" ]; then
    # no test directory passed, generate one and clean it up on exit
    TESTDIR=$(mktemp -d --tmpdir 'authdns-lint.XXXXXX')
    CLEANUP=yes
fi

echo "Using $TESTDIR as the output working directory (gdnsd etc)"
mkdir -p "$TESTDIR/zones"
mkdir -p "$TESTDIR/geoip"
mkdir -p "$TESTDIR/state"

echo "Generating zonefiles from zone templates"
utils/authdns-gen-zones.py templates "$TESTDIR/zones"

if [ "$(find "$TESTDIR/zones" | wc -l)" -le 10 ]; then
    die "less than 10 zones, something's probably wrong, aborting";
fi

echo "Generating gdnsd config"
for realf in config geo-maps geo-resources; do
    cp -f $realf "$TESTDIR/"
done
for mockf in discovery-map discovery-geo-resources discovery-metafo-resources discovery-states; do
    cp -f utils/mock_etc/$mockf "$TESTDIR/"
done
cp -f utils/mock_etc/geoip/GeoIP2-City.mmdb "$TESTDIR/geoip/"
cp -f admin_state "$TESTDIR/state/"

# The mock variant of config-options is used to set the state_dir so that we
# can test parsing of admin_state
echo "state_dir = \"$TESTDIR/state\"" >"$TESTDIR/config-options"

gdnsd -c "$TESTDIR" checkconf
