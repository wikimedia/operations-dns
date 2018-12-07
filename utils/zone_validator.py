#!/usr/bin/python3
"""Zone Validator: a WMF-specific DNS zone files consistency check validator

Automatically parse and validate the internal 'wmnet' zonefile and all the reverse zonefiles in
the templates directory.
"""
import argparse
import glob
import ipaddress
import logging
import os
import re
import sys

from collections import Counter, defaultdict


# Main logger, streams to stderr
logging.basicConfig(level=logging.INFO, format='%(name)s[%(levelname)s] %(message)s')
logger = logging.getLogger('zone-validator')
# Matches asset tags names of the form wmfNNNN, case-insensitive
ASSET_TAG_PATTERN = re.compile(r'^wmf[0-9]{4}\.mgmt\.', re.I)
# List of prefixes of mgmt records that should skip the check for asset tag records
NO_ASSET_TAG_PREFIXES = []
IPV4_REVERSE_DOMAIN = 'in-addr.arpa.'
IPV6_REVERSE_DOMAIN = 'ip6.arpa.'


class PrintList(list):
    """Custom list class to pretty print the results, one per line, indented."""

    def __str__(self):
        """Define a specific string representation, calling str() on the lists's items."""
        if len(self):
            return '\n    ' + '\n    '.join(str(item) for item in self)
        else:
            return '[]'


class DNSRecord(object):
    """A DNS Record object, immutable."""
    # Specify the fields that can be set, also optimizing them.
    __slots__ = ['name', 'type', 'value', 'file', 'line', 'comment']

    def __init__(self, name, record_type, value, file, line, comment=''):
        """Constructor of as DNSRecord object."""
        # Use object's __setattr__ to bypass the its own __setattr__.
        object.__setattr__(self, 'name', name)
        object.__setattr__(self, 'type', record_type)
        object.__setattr__(self, 'value', value)
        object.__setattr__(self, 'file', file)
        object.__setattr__(self, 'line', line)
        object.__setattr__(self, 'comment', comment)

    def __setattr__(self, *args):
        """Do not allow to modify existing attributes."""
        raise AttributeError("can't set attribute")

    def __delattr__(self, *args):
        """Do not allow to delete existing attributes."""
        raise AttributeError("can't delete attribute")

    def __repr__(self):
        """Representation of the object."""
        return '<DNSRecord {o.name} {o.type} {o.value} ({o.file}:{o.line}) {o.comment}>'.format(
            o=self)

    def __str__(self):
        """String representation of the object."""
        return '{o.file}:{o.line} {o.name} {o.type} {o.value} {o.comment}'.format(o=self)

    def __hash__(self):
        """Make the class hashable based only on the DNS-meaningful part of the data."""
        return hash((self.name, self.type, self.value))

    def __eq__(self, other):
        """Equality comparison operator, required to use instances as dictionary keys."""
        if type(other) != DNSRecord:
            return False

        return self.name == other.name and self.type == other.type and self.value == other.value

    def get_name(self):
        """Return the record's name, raise ValueError if unable."""
        if self.type in ('A', 'AAAA'):
            return self.name
        elif self.type == 'PTR':
            return self.value
        else:
            raise ValueError('Unrecognized record type: %s', self.type)

    def get_ip(self):
        """Return the record's IP, raise ValueError if unable."""
        if self.type in ('A', 'AAAA'):
            return self.value

        elif self.type == 'PTR':  # Reverse the PTR back to IP
            reverse = self.name.split('.')[:-3][::-1]
            if self.name.endswith(IPV6_REVERSE_DOMAIN):
                addr = ':'.join(''.join(reverse[i:i+4]) for i in range(0, 32, 4))
            elif self.name.endswith(IPV4_REVERSE_DOMAIN):
                addr = '.'.join(reverse)
            else:
                raise ValueError('Unknown PTR type: {addr}'.format(addr=self.name))

            return str(ipaddress.ip_address(addr))


class ZonesValidator(object):
    """Zones Validator main class."""

    def __init__(self, zonefiles, level):
        """Constructor, initialize variables and reporter logger."""
        self.zonefiles = zonefiles
        self.level = level

        # Parsing temprorary variables
        self.origin = None
        self.zone = None
        self.previous_full_line = None

        # Data structures to save parsed data
        self.names = {'IP': defaultdict(lambda: defaultdict(PrintList)),
                      'PTR': defaultdict(lambda: defaultdict(PrintList))}
        self.ips = defaultdict(lambda: defaultdict(PrintList))
        self.ptrs = defaultdict(lambda: defaultdict(PrintList))
        self.unique_records = defaultdict(PrintList)
        self.fqdn_mgmt_prefixes = set()
        self.origins = set()

        # Analyzer stats
        self.max_infraction = logging.NOTSET
        self.counters = Counter()

        self.reporter = logging.getLogger('zone-validator.report')
        self._setup_reporter()

    def validate(self):
        """Parse all the configured zonfiles and validate the records.

        Return:
            int: 0 if no errors are found, 1 otherwise.
        """
        self._parse()
        self._validate()

        # Log summary line
        if sum(self.counters.values()) == 0:
            logger.info('All records are valid!')
        else:
            epilogue = ''
            message = ', '.join('{n} {name}(S)'.format(n=value, name=logging.getLevelName(key))
                                for key, value in self.counters.items())
            if self.level >= logging.ERROR:
                epilogue = ' (WARNING(S) were suppressed, set -w/--warning to show them)'
            logger.log(self.max_infraction, '%s were found!%s', message, epilogue)

        # The return code depends on the maximum level of logged message in the checks report logger
        if self.max_infraction >= logging.ERROR:
            return 1
        else:
            return 0

    @staticmethod
    def is_mgmt_subhost(name):
        """Return True if the record has more than 4 levels.

        Example: <subrecord>.<record>.mgmt.<dc>.wmnet.
        """
        return len(name.split('.')) > 5  # All names have the tailing dot

    def err(self, message, *args):
        """Log in the reporter logger with level ERROR."""
        self._log(logging.ERROR, message, *args)

    def warn(self, message, *args):
        """Log in the reporter logger with level WARNING."""
        self._log(logging.WARNING, message, *args)

    def _log(self, level, message, *args):
        """Log in the reporter logger with the given level, update stats and maximum level."""
        self.counters[level] += 1
        if self.max_infraction < level:
            self.max_infraction = level

        self.reporter.log(level, message, *args)

    def _parse(self):
        """Parse all the configured zonefiles."""
        for zonefile in self.zonefiles:
            logger.debug('Parsing zonefile %s', zonefile)
            self.zone = os.path.basename(zonefile)
            # Until the first $ORIGIN line the filename itself is the $ORIGIN value
            self.origin = self.zone + '.'
            self.origins.add(self.origin)

            with open(zonefile, 'r') as f:
                for lineno, line in enumerate(f.readlines()):
                    self._process_line(line, lineno)
                    if not line.startswith(' '):
                        self.previous_full_line = line

    def _process_line(self, line, lineno):
        """Process a zone file line."""
        stripped_line = line.strip()
        if not line or not stripped_line or line[0] == ';' or stripped_line[0] == ';':
            return  # Empty line or comment

        elif line.startswith('$ORIGIN '):
            self.origin = line.replace('{{ zonename }}', self.zone).split()[1]
            if self.origin[-1] != '.':
                raise ValueError(
                    'Unsupported not fully qualified $ORIGIN: {file}:{lineno} {line}'.format(
                        file=self.zone, lineno=lineno, line=line))

            self.origins.add(self.origin)

        elif self.origin is not None and self.origin.startswith('svc.'):
            return  # Skip svc.* ORIGINs

        elif ' IN A ' in line or ' IN AAAA ' in line:
            if line.startswith(' '):
                name = self.previous_full_line.split()[0]  # Name from previous_full_line
                _, _, record_type, ip, *comments = line.split(None, 4)
            else:
                name, _, _, record_type, ip, *comments = line.split(None, 5)

            if name[-1] == '.':
                raise ValueError('Unsupported fully qualified name: {file}:{lineno} {line}'.format(
                    file=self.zone, lineno=lineno, line=line))

            fqdn = '.'.join([name, self.origin])
            comment = comments[0].strip() if comments else ''
            record = DNSRecord(fqdn, record_type, ip, self.zone, lineno, comment=comment)

            self.unique_records[record].append(record)
            self.names['IP'][self.origin][ip].append(record)
            self.ips[self.origin][fqdn].append(record)
            if self._is_mgmt(self.origin):
                self.fqdn_mgmt_prefixes.add('.'.join(fqdn.split('.')[:2]))

        elif ' IN PTR ' in line:
            ip, _, _, record_type, fqdn, *comments = line.split(None, 5)
            if '.svc.' in fqdn:
                return  # Skip .svc. records

            if ip[-1] == '.':
                raise ValueError('Unsupported fully qualified PTR: {file}:{lineno} {line}'.format(
                    file=self.zone, lineno=lineno, line=line))

            ptr = '.'.join([ip, self.origin])
            comment = comments[0].strip() if comments else ''
            record = DNSRecord(ptr, record_type, fqdn, self.zone, lineno, comment=comment)

            self.unique_records[record].append(record)
            self.names['PTR'][self.origin][ptr].append(record)
            self.ptrs[self.origin][fqdn].append(record)
            if '.mgmt.' in fqdn:
                self.fqdn_mgmt_prefixes.add('.'.join(fqdn.split('.')[:2]))

    def _validate(self):
        """Validate all the parsed records."""
        duplicates = [records for records in self.unique_records.values() if len(records) > 1]
        if not duplicates:
            logger.info('No global duplicate record found')
        for duplicate in duplicates:
            self.err('Global duplicate records found: %s', duplicate)

        for origin in self.origins:
            is_mgmt = self._is_mgmt(origin)
            logger.info('Validating $ORIGIN %s (is_mgmt=%s)', origin, is_mgmt)
            self._validate_origin_names(origin, is_mgmt)
            self._validate_origin_ips(origin, is_mgmt)
            self._validate_origin_ptrs(origin, is_mgmt)

    def _validate_origin_names(self, origin, is_mgmt):
        """Validate IPs and PTRs in the given origin."""
        for label, names in self.names.items():
            for value, records in names[origin].items():
                if not records:
                    continue

                if is_mgmt:
                    self._validate_mgmt_names(origin, value, records, label)
                else:
                    self._validate_names(value, records, label)

    def _validate_mgmt_names(self, origin, ip, records, label):
        """Validate all the mgmt names for the given IP/PTR, expecting two entries."""
        if len(records) == 1:  # Check if for this item it's ok to have only one entry.
            name = records[0].get_name()
            if ZonesValidator.is_mgmt_subhost(name):
                logger.debug('Skipping 5th level mgmt record: %s', records[0])
                return
            if any(name.startswith(prefix) for prefix in NO_ASSET_TAG_PREFIXES):
                logger.debug('Skipping no asset tag mgmt record: %s', records[0])
                return

        if len(records) != 2:  # We expected 2 records for each mgmt, hostname and WMF asset tag.
            if len(records) > 2:
                level = logging.ERROR
            else:
                level = logging.WARNING
            self._log(level, "Found %d name(s) for %s '%s', expected 2 (hostname, wmfNNNN): %s",
                      len(records), label, ip, records)

        # Check that there is one and only one WMF asset tag set for this name.
        matches = [ASSET_TAG_PATTERN.match(record.get_name()) for record in records]
        if (all(match is None for match in matches) or
                sum(match is not None for match in matches) != 1):
            self.warn("Expected one asset tag name matching '%s', got: %s",
                      ASSET_TAG_PATTERN.pattern, records)

    def _validate_names(self, value, records, label):
        """Validate record names for all the given IP/PTR, only one record expected."""
        if len(records) != 1:
            level = logging.WARNING
            if any(ipaddress.ip_address(record.get_ip()).is_private for record in records):
                level = logging.ERROR
            self._log(level, "Found %d name(s) for %s '%s', expected 1: %s",
                      len(records), label, value, records)

    def _validate_origin_ips(self, origin, is_mgmt):
        """Validate PTRs for all the IPs in the given origin."""
        for name, records in self.ips[origin].items():
            if not records:
                continue

            self._validate_mgmt_exists(name, records, is_mgmt)
            self._validate_ips(origin, name, records, is_mgmt)
            self._validate_ips_ptrs(origin, name, records, is_mgmt)

    def _validate_origin_ptrs(self, origin, is_mgmt):
        """Validate IPs for all the PTRs in the given origin."""
        is_v6 = IPV6_REVERSE_DOMAIN in origin
        for name, records in self.ptrs[origin].items():
            if not records:
                continue

            self._validate_ptrs_ips(origin, name, records, is_mgmt)
            if not is_v6:  # The management network is IPv4 only.
                self._validate_mgmt_exists(name, records, is_mgmt)

    def _validate_ips(self, origin, name, records, is_mgmt):
        """Validate the IPs for the given record name."""
        if len(records) == 2 and not is_mgmt:  # Two records, must be one IPv4 and one IPv6
            if sum(ipaddress.ip_address(record.value).version for record in records) != 10:
                self.warn("Found %d IP(s) for name '%s', expected 1 v4 and 1 v6: %s",
                          len(records), name, records)
        elif len(records) != 1:
            self.err("Found %d IP(s) for name '%s', expected 1: %s", len(records), name, records)

    def _validate_ips_ptrs(self, origin, name, records, is_mgmt):
        """Validate the PTR records of all the IPs."""
        if is_mgmt and ZonesValidator.is_mgmt_subhost(name):
            logger.debug('Skipping 5th level mgmt name %s', name)
            return

        ptrs = [record.name for orig in self.origins for record in self.ptrs[orig][name]]
        if ptrs:
            level = logging.ERROR
        else:
            level = logging.WARNING

        for record in records:
            ptr = ipaddress.ip_address(record.value).reverse_pointer + '.'
            if ptr not in ptrs:
                self._log(level, "Missing PTR '%s' for name '%s' and IP '%s', PTRs are: %s",
                          ptr, name, record.value, ptrs)

    def _validate_ptrs_ips(self, origin, name, records, is_mgmt):
        """Validate the IP records of all the PTRs."""
        if is_mgmt and ZonesValidator.is_mgmt_subhost(name):
            logger.debug('Skipping 5th level mgmt name %s', name)
            return

        ips = [record.value for orig in self.origins for record in self.ips[orig][name]]
        if ips:
            level = logging.ERROR
        else:
            level = logging.WARNING

        for record in records:
            try:
                ip = record.get_ip()
                if ip not in ips:
                    self._log(level, "Missing IP '%s' for name '%s' and PTR '%s', IPs are: %s",
                              ip, name, record.name, ips)
            except ValueError as e:
                self._log(level, "Missing unknown IP for name '%s' and PTR '%s', IPs are: %s",
                          name, record.name, ips)
                self.err("Unable to reverse PTR to IP for record '%s': %s", record, e)

    def _validate_mgmt_exists(self, name, records, is_mgmt):
        """Validate that the mgmt interface exists if not Ganeti VMs."""
        if is_mgmt:
            return

        splitted_name = name.split('.')
        if len(splitted_name) > 4:
            logger.debug('Skipping mgmt check for 4th level name: %s', name)
            return

        if name.split('.')[0] + '.mgmt' in self.fqdn_mgmt_prefixes:
            return

        ganeti = [record for record in records if 'ganeti' in record.comment.lower()]
        if not ganeti:
            self.warn("Missing mgmt record for name '%s' and record(s): %s", name, records)

        elif len(ganeti) < len(records):
            missing = PrintList([record for record in records if record not in ganeti])
            self.warn("Missing ganeti comment for name '%s' in record(s): %s", name, missing)

    def _is_mgmt(self, origin):
        """Return True if the given origin is a management one."""
        if origin.startswith('mgmt.'):
            return True

        if not origin.endswith(IPV4_REVERSE_DOMAIN):
            return False

        # Detect if it's a mgmt reverse ORIGIN by checking the first items
        for i, name in enumerate(self.ptrs[origin].keys()):
            if name.split('.')[-4] == 'mgmt':
                return True
            if i > 5:
                break

        return False

    def _setup_reporter(self):
        """Setup the checks reporter logger, streams to stdout."""
        self.reporter.propagate = False
        self.reporter.raiseExceptions = False

        formatter = logging.Formatter(fmt='%(levelname)s: %(message)s')
        handler = logging.StreamHandler(stream=sys.stdout)
        handler.setFormatter(formatter)
        handler.setLevel(self.level)
        self.reporter.addHandler(handler)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-w', '--warning', action='store_true',
                        help='Print also warnings, by default only errors are reported.')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Set log level to debug.')

    return parser.parse_args()


def main():
    """Run the script."""
    args = parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)

    if args.warning:
        level = logging.WARNING
    else:
        level = logging.ERROR

    # Collect all the zonefiles
    base_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), os.pardir, 'templates')
    zonefiles = [os.path.join(base_path, zone) for zone in ('wmnet', 'wikimedia.org')]  # Default zones
    zonefiles += glob.glob(os.path.join(base_path, '*.in-addr.arpa'))  # IPv4 reverse zonefiles
    zonefiles += glob.glob(os.path.join(base_path, '*.ip6.arpa'))  # IPv6 reverse zonefiles

    validator = ZonesValidator(zonefiles, level)
    return validator.validate()


if __name__ == '__main__':
    sys.exit(main())
