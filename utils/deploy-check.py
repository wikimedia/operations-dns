#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# This script handles pre-validation of deployability as well as the actual
# deployment itself.  This script must run from the root directory of the repo,
# and it relies on the utils/gen-zones.py script there.  It has two modes of
# operation:
#
# * By default (with no arguments) it does a mock deployment test suitable for
# use in CI or in local testing with appropriate packages installed (python3,
# python3-jinja2, python3-git, gdnsd), using only temporary directories and the
# mocked production puppet-driven configuration from utils/mock_etc.
#
# * Deployment mode is triggered by the --deploy argument, and should only be
# used on actual puppetized authdns servers, and will in the normal case be
# invoked by puppet's "authdns-local-update" script, which in turn is normally
# driven by the administrator running "authdns-update" on one host which ssh's
# to the rest.
#
# In the deploy case, the test deploy in the temporary directory copies the
# real, deployed copies of the files (e.g. from /etc/gdnsd/) into the test
# directory to validate the combined ops/puppet and ops/dns live configuration
# (as opposed to the mock files used for CI), and then on success the relevant
# files are deployed to the real system location and a gdnsd "replace" or
# "reload-zones" is triggered as appropriate.

import argparse
import os
import subprocess
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory

# Config files supplied by ops/dns
DNS_CFG = [
    'config',
    'geo-maps',
    'geo-resources',
]

# Config files supplied by puppet, or mocked if not deploying
PUPPET_CFG = [
    'config-options',
    'discovery-map',
    'discovery-geo-resources',
    'discovery-metafo-resources',
    'discovery-states',
]

# Name of the GeoIP database file in $etc/geoip/
GEOIP_DB = 'GeoIP2-City.mmdb'

# pathnames for installed gdnsd binaries
GDNSD_BIN = '/usr/sbin/gdnsd'
GDNSDCTL_BIN = '/usr/bin/gdnsdctl'

# Git repository which contains generated DNS
GEN_DNS_GIT = 'https://netbox-exports.wikimedia.org/dns.git'


def parse_args():
    """Sets up argument parser and its arguments, returns args"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--deploy',
                        help='Validate and deploy on a real authdns server',
                        action='store_true',
                        default=0)
    parser.add_argument('-n', '--no-gdnsd',
                        help='No gdnsd installed (no checkconf/reload)',
                        action='store_true',
                        default=0)
    parser.add_argument('-s', '--skip-reload',
                        help='Deploy with checking, but without reload',
                        action='store_true',
                        default=0)
    parser.add_argument('-g', '--generated-include', help='Specify path to generated include files', default='')
    return parser.parse_args()


def safe_cmd(args):
    """Exec args, raise w/ stderr if non-zero exit, otherwise no stderr"""
    cmd = subprocess.Popen(args, stderr=subprocess.PIPE)
    (_, p_err) = cmd.communicate()
    if cmd.returncode != 0:
        raise Exception('Command %s failed with exit code %i, stderr:\n%s' %
                        (' '.join(args),
                         cmd.returncode,
                         p_err.decode('utf-8')))


def deploy_zones(srcdir, dstdir):
    """Deploy zonefiles with deletions"""
    need_reload = False
    for zfile in srcdir.iterdir():
        dst = dstdir / zfile.name
        if zfile.is_dir():
            print(" -- Descending to subdirectory: " + zfile.name)
            if not dst.exists():
                dst.mkdir()
            need_reload |= deploy_zones(Path(srcdir, str(zfile.name)), dst)
            print(" -- Done with subdir: " + zfile.name)
        elif not dst.exists():
            print(" -- Zone added: " + zfile.name)
            need_reload = True
            shutil.copy(str(zfile), str(dst))
        elif dst.read_text() != zfile.read_text():
            print(" -- Zone changed: " + zfile.name)
            need_reload = True
            shutil.copy(str(zfile), str(dst))
    for dst in dstdir.iterdir():
        if not Path(srcdir, dst.name).exists():
            print(" -- Zone deleted: " + dst.name)
            need_reload = True
            dst.unlink()
    return need_reload


def deploy_cfg(srcdir, dstdir):
    """Deploy the simple text configs"""
    need_replace = False
    for cfg in DNS_CFG:
        src = srcdir / cfg
        dst = dstdir / cfg
        if not dst.exists() or dst.read_text() != src.read_text():
            print(" -- Config file changed: " + cfg)
            need_replace = True
            shutil.copy(str(src), str(dst))
    return need_replace


def setup_gen_repo(gen_dns_git):
    """Make a checkout of the generated DNS git repository in a temporary place."""
    path = TemporaryDirectory(prefix='dns-check-generated.')
    print("Checking out generated DNS to", path.name)
    safe_cmd(('git', 'clone', gen_dns_git, path.name))
    return path


def setup_tdir(deploy, tdir, tdir_zones, gdir):
    """Setup all contents of the test directory, return srcdir"""

    # Create subdirs in tdir:
    tdir_geoip = tdir / 'geoip'
    tdir_zones.mkdir()
    tdir_geoip.mkdir()

    print(' -- Generating zonefiles from zone templates', flush=True)
    subprocess.run(['utils/gen-zones.py', str(tdir_zones)], check=True)
    if len(list(tdir_zones.iterdir())) < 10:
        raise Exception('Less than 10 zones generated, something is wrong')
    print(' -- Copying automatically generated zone files under target tree')
    shutil.copytree(str(gdir), os.path.join(str(tdir), 'zones', 'netbox'), ignore=lambda x, y: ['.git'])
    print(' -- Copying repo-driven real config files')
    for realcf in DNS_CFG:
        shutil.copy(str(realcf), str(tdir))

    # Choose source path based on deploy vs mock-test
    if deploy:
        sdesc = 'puppetized'
        srcdir = Path('/', 'etc', 'gdnsd')
    else:
        sdesc = 'mock'
        srcdir = Path('utils', 'mock_etc')
    srcdir_geoip = srcdir / 'geoip'

    print(' -- Copying %s config and GeoIP from %s' % (sdesc, srcdir))
    for pcfg in PUPPET_CFG:
        shutil.copy(str(srcdir / pcfg), str(tdir))
    shutil.copy(str(srcdir_geoip / GEOIP_DB),
                str(tdir_geoip), follow_symlinks=False)

    return srcdir


def deploy_check(deploy, skip_reload, no_gdnsd, tdir, gdir):
    """Does the core work of the script"""

    print('Assembling and testing data in %s' % tdir)
    tdir_zones = tdir / 'zones'
    srcdir = setup_tdir(deploy, tdir, tdir_zones, gdir)

    # Check for tabs, which we disallow
    print(' -- Checking for illegal tabs in zonefiles')
    safe_cmd(['./utils/check-tabs.sh'])

    # Validate processed zone output data using WMF rules
    print(' -- Running zone_validator to check WMF rules')
    safe_cmd([
        'python3',
        './utils/zone_validator.py',
        '--error',
        '--zones_dir',
        str(tdir_zones),
        '--ignores',
        'MISSING_ASSET_TAG,MISSING_MGMT_FOR_NAME,TOO_FEW_MGMT_NAMES',
    ])

    # Checkconf, unless we shouldn't
    if no_gdnsd:
        print(' -- Skipping checkconf due to --no-gdnsd')
    else:
        print(' -- Running %s checkconf on %s' % (GDNSD_BIN, tdir), flush=True)
        safe_cmd([GDNSD_BIN, '-c', str(tdir), 'checkconf'])
        if not deploy:
            print(' -- Mocked checkconf is OK')
        else:
            print(' -- Preflight checkconf is OK')

    # Done here if not deploying
    if not deploy:
        return

    # Deploy things!
    print('Deploying from %s to system dirs' % tdir)
    need_reload = deploy_zones(tdir_zones, srcdir / 'zones')
    need_replace = deploy_cfg(tdir, srcdir)

    # Maybe take action!
    if not need_replace and not need_reload:
        print('No action needed, zones and config files unchanged')
    elif no_gdnsd:
        print('Skipping reload/replace due to --no-gdnsd')
    elif skip_reload:
        print('Skipping reload/replace due to --skip-reload')
    elif need_replace:
        print('Replacing gdnsd to update config and zones', flush=True)
        subprocess.run([GDNSDCTL_BIN, 'replace'], check=True)
    elif need_reload:
        print('Reloading gdnsd zonefiles', flush=True)
        subprocess.run([GDNSDCTL_BIN, 'reload-zones'], check=True)
    print('OK')


def main():
    """main"""
    args = parse_args()

    # Sanity check we're executing in our repo root
    gitr = Path('.gitreview')
    if not gitr.is_file() or 'operations/dns' not in gitr.read_text():
        raise Exception('Execute in root of an operations/dns repo clone')

    if not args.generated_include:
        # do a checkout of the generated DNS repository into a temporary for testing purposes.
        gtmpdir = setup_gen_repo(GEN_DNS_GIT)
        gdir = gtmpdir.name
    else:
        # assume the environment variable is correct.
        gtmpdir = None
        gdir = args.generated_include

    try:
        # Execute the core deploy_check with a Path object for the temp dir which
        # is automatically cleaned up via context:
        with TemporaryDirectory(prefix='dns-check.') as tdir:
            deploy_check(args.deploy, args.skip_reload, args.no_gdnsd, Path(tdir), gdir)
    finally:
        # clean up gen dns checkout if necessary
        if gtmpdir is not None:
            gtmpdir.cleanup()


if __name__ == '__main__':
    main()

# vim: ts=4 sts=4 et ai shiftwidth=4 fileencoding=utf-8
