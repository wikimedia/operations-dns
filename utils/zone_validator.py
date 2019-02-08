#!/usr/bin/python3
"""Zone Validator: a WMF-specific DNS zone files consistency check validator

The script parses the following zones in the templates/ directory:
- wmnet
- wikimedia.org
- *.in-addr.arpa
- *.ip6.arpa

Violations will be reported to stdout, logging to stderr.

Parsing will fail in any of the following cases:
- all $ORIGINs must be fully qualified, relative ORIGINs are not supported.
- all A/AAAA/PTR records must be relative to their $ORIGIN, fully qualified
  records are not supported.
- unable to reverse a PTR record.
- unable to instantiate the IP for A/AAAA records
- wrong IP version for A/AAAA records (IPv4 for AAAA or IPv6 for A)

While parsing the following records are skipped:
- all records that are not A, AAAA or PTR.
- any $ORIGINs starting with 'svc.' is skipped completely.
- any PTR that has '.svc.' in the name.

In addition any line with a comment of the form:
    wmf-zone-validator-ignore=$NAME_OF_VIOLATION
will be ignored for that particular violation. The comment can contain
multiple ignore blocks.

It then performs the following global validations:
- check of any duplicate record across all parsed records
  [Error.GLOBAL_DUPLICATE]

It then iterate over all ORIGINs, detecting (best effort) if it's a management
one or not (reported as is_mgmt=True/False in debug mode) and performs the
following ORIGIN-specific validations:
- Any ORIGIN
  - expect a correct PTR exists for each direct record
    - other PTRs found, maybe a typo
      [Error.MISSING_OR_WRONG_IP_FOR_NAME_AND_PTR]
    - no PTR found [Warning.MISSING_PTR_FOR_NAME_AND_IP]
  - expect a correct IP exists for each PTR record
    - other IPs found, possibly a typo
      [Error.MISSING_OR_WRONG_PTR_FOR_NAME_AND_IP]
    - no IP found [Warning.MISSING_IP_FOR_NAME_AND_PTR]

- Management ORIGIN
  - ignore any 5th level mgmt record (i.e. $vlan_eth.$hostname.mgmt.$dc.wmnet)
  - expect 2 A and 2 PTR records for {$hostname,$asset_tag}.mgmt.$dc.wmnet
    - more than 2 found [Error.TOO_MANY_MGMT_NAMES]
    - 1 found [Warning.TOO_FEW_MGMT_NAMES]
      - ignore if record start with one of the NO_ASSET_TAG_PREFIXES
    - 2 found
      - no asset tag is found [Warning.MISSING_ASSET_TAG]
      - multiple asset tags found [Error.MULTIPLE_ASSET_TAGS]
  - expect 1 IP for each record name [Error.MULTIPLE_IPS_FOR_NAME]

- Regular ORIGIN
  - expect 1 IP only for each name
    - any IP is private [Error.TOO_MANY_NAMES]
    - all IP are public [Warning.TOO_MANY_PUBLIC_NAMES]
  - expect a management record [Warning.MISSING_MGMT_FOR_NAME]
    - unless is IPv6 (management network is v4)
    - unless is a 4th level name (i.e. foo.$host.$dc.wmnet)
    - unless is a Ganeti VMs (detected via the comment)
      - expect all Ganeti records have the comment
        [Error.MISSING_GANETI_COMMENT]
  - expect 1 record per name unless dual stack [Error.MULTIPLE_IPS_FOR_NAME]
    - if 2 records, expect dual stack (v4 + v6)
      [Warning.MISSING_DUAL_STACK_FOR_NAME]

TODO:
- add support for frack management records (are currently skipped being a 5th
  level mgmt name: $host.mgmt.frack.eqiad.wmnet)
"""
import argparse
import glob
import ipaddress
import json
import logging
import os
import re
import sys

from collections import Counter, defaultdict
from enum import Enum, unique


# Main logger, streams to stderr
logging.basicConfig(level=logging.INFO, format='%(name)s[%(levelname)s] %(message)s')
logger = logging.getLogger('zone-validator')
# Matches asset tags names of the form wmfNNNN, case-insensitive
ASSET_TAG_PATTERN = re.compile(r'^wmf[0-9]{4}\.mgmt\.', re.I)
# List of prefixes of mgmt records that should skip the check for asset tag records
NO_ASSET_TAG_PREFIXES = []
IPV4_REVERSE_DOMAIN = 'in-addr.arpa.'
IPV6_REVERSE_DOMAIN = 'ip6.arpa.'


class ViolationBase(Enum):
    """Base Enum class for all Validations."""

    @property
    def level(self):
        """The logging level of this type of validations.

        Returns:
            int: one of the logging module log level.
        """
        raise NotImplementedError('Property level not defined in class {name}'.format(name=self.__class__.__name__))

    @property
    def color(self):
        """The color to use to highlight this type of validations.

        Returns:
            str: the color code escape sequence for this type of validations.
        """
        raise NotImplementedError('Property color not defined in class {name}'.format(name=self.__class__.__name__))

    def __str__(self):
        """String representation of the instance, color coded.

        Arguments and return value:
            According to https://docs.python.org/3/reference/datamodel.html
        """
        return '{o.color}{o.value}|{o.name}\x1b[0m:'.format(o=self)

    def __lt__(self, other):
        """Less than comparator for the instance.

        Arguments and return value:
            According to https://docs.python.org/3/reference/datamodel.html
        """
        return self.value + self.name < other.value + other.name

    def ignore(self, comment):
        """Check if the comment include the ignore for this violation.

        Arguments:
            comment (str): the comment line to check for the ignore string.

        Returns:
            bool: whether the violation should be ignored or not.
        """
        return 'wmf-zone-validator-ignore=' + self.name in comment


@unique
class Error(ViolationBase):
    """Error validations."""

    # Codes in the E001-E100 range are generic DNS errors
    GLOBAL_DUPLICATE = 'E001'
    MISSING_OR_WRONG_IP_FOR_NAME_AND_PTR = 'E002'
    MISSING_OR_WRONG_PTR_FOR_NAME_AND_IP = 'E003'
    # Codes in the E101-E999 range are WMF-specific errors
    MULTIPLE_IPS_FOR_NAME = 'E101'
    TOO_MANY_MGMT_NAMES = 'E102'
    TOO_MANY_NAMES = 'E103'
    MULTIPLE_ASSET_TAGS = 'E104'
    MISSING_GANETI_COMMENT = 'E105'

    @property
    def level(self):
        """Return logging Error level."""
        return logging.ERROR

    @property
    def color(self):
        """Return the red color escape sequence."""
        return '\x1b[31;1m'


@unique
class Warning(ViolationBase):
    """Warning validations."""

    # Codes in the W001-W100 range are generic DNS warnings
    MISSING_IP_FOR_NAME_AND_PTR = 'W001'
    MISSING_PTR_FOR_NAME_AND_IP = 'W002'
    # Codes in the W101-W999 range are WMF-specific warnings
    MISSING_ASSET_TAG = 'W101'
    MISSING_DUAL_STACK_FOR_NAME = 'W102'
    MISSING_MGMT_FOR_NAME = 'W103'
    TOO_FEW_MGMT_NAMES = 'W104'
    TOO_MANY_PUBLIC_NAMES = 'W105'

    @property
    def level(self):
        """Return logging Warning level."""
        return logging.WARNING

    @property
    def color(self):
        """Return the yellow color escape sequence."""
        return '\x1b[33;1m'


class ViolationFactory:
    """Violation factory class to instantiate ViolationBase subclasses."""

    @staticmethod
    def new(method_name):
        """Instantiate the appropriate ViolationBase subclass based on the method name.

        Arguments:
            func_name (str): the name of the method called in ViolationsReporter.

        Returns:
            ViolationBase: an instance of a ViolationBase subclass.

        Raises:
            AttributeError: if the violation doesn't exists in the chosen subclass.
            ValueError: if unable to recognize the violation subclass from the method name.

        """
        name = method_name.upper()
        if name.startswith('E_'):
            return getattr(Error, name[2:])
        elif name.startswith('W_'):
            return getattr(Warning, name[2:])
        else:
            raise ValueError('Unrecognized validation name {name}'.format(name=name))

    @staticmethod
    def find(name):
        """Find and instantiate the appropriate ViolationBase subclass based on the violation name.

        Arguments:
            name (str): the violation name to look for.

        Returns:
            ViolationBase: an instance of a ViolationBase subclass.

        Raises:
            ValueError: if unable to find the violation in any of the ViolationBase subclasses.

        """
        for cls in (Error, Warning):
            try:
                return getattr(cls, name)
            except AttributeError:
                pass  # Continue searching

        raise ValueError('Unable to find violation {name} in any of the ViolationBase subclasses'.format(name=name))


class ViolationsReporter:
    """Reporter of violations class."""

    def __init__(self, level, ignores=None, shows=None):
        """Initialize the instance.

        Arguments:
            level (int): the error level to report, any violation with a level lower than the one provided will not be
                printed. The value must be one of the log level from the logging module.
            ignores (list, optional): the list of ViolationBase instances to ignore.
            shows (list, optional): the list of ViolationBase instances names to show. If set overrides the ignores one.
        """
        self.level = level
        self.logger = logging.getLogger('zone-validator.reporter')
        self._setup_logger()
        self.max_infraction = logging.NOTSET
        self.counters = Counter()
        self.ignores = ignores or []
        self.shows = shows or []
        self.ignored_violations = 0
        self.ignored_lines = 0

    def log_results(self):
        """Log the final results.

        Returns:
            dict: the summary of violations in a dict with as keys the violation names and as value the number of
                violations.

        """
        # CRITICAL logging level is used to ensure this is printed. This logger doesn't print level info.
        if self.shows:
            logger.info('Only the following violations (if any) were shown: %s', ', '.join(v.name for v in self.shows))
        elif self.ignores:
            logger.info('The following violations (if any) were ignored: %s', ', '.join(v.name for v in self.ignores))

        violations = {}
        if sum(self.counters.values()) == 0:
            self.logger.log(logging.CRITICAL, 'No violation found!')
            return violations

        violation_counts = Counter()
        violations_found = []
        for violation, count in sorted(self.counters.items()):
            violations_found.append('{violation} {count}'.format(violation=violation, count=count))
            violation_counts[violation.level] += count
            violations['|'.join([violation.value, violation.name])] = count

        self.logger.log(logging.CRITICAL, 'Summary of violations:\n    %s', '\n    '.join(violations_found))

        self.logger.log(
            logging.CRITICAL,
            ('RESULT: \x1b[31;1m%d Errors\x1b[0m, \x1b[33;1m%d Warnings\x1b[0m, %d Ignored violations, '
             '%d Ignored lines'),
            violation_counts[logging.ERROR],
            violation_counts[logging.WARNING],
            self.ignored_violations,
            self.ignored_lines)

        return violations

    def _err(self, records, message, *args):
        """Log a violation of type error.

        Arguments:
            records (list): list of DNSRecord instances to which the violation refers to.
            message (str): the message string to log, it will be passed to the logger, hence % replacements are
                available.
            *args (list): list of positional arguments. They will be passed to the logger for the % replacements.
        """
        self._log(logging.ERROR, records, message, *args)

    def _warn(self, records, message, *args):
        """Log a violation of type warning.

        Arguments:
            records (list): list of DNSRecord instances to which the violation refers to.
            message (str): the message string to log, it will be passed to the logger, hence % replacements are
                available.
            *args (list): list of positional arguments. They will be passed to the logger for the % replacements.
        """
        self._log(logging.WARNING, records, message, *args)

    def _log(self, level, records, message, *args):
        """Log a violation unless in the ignore list and update statistics.

        Arguments:
            level (int): the logging level to use for this message.
            records (list): list of DNSRecord instances to which the violation refers to.
            message (str): the message string to log, it will be passed to the logger, hence % replacements are
                available.
            *args (list): list of positional arguments. They will be passed to the logger for the % replacements.
        """
        violation = ViolationFactory.new(sys._getframe(2).f_code.co_name)
        if (self.shows and violation not in self.shows) or violation in self.ignores:
            self.ignored_violations += 1
            return

        if all(violation.ignore(record.comment) for record in records):
            for record in records:
                self.ignored_lines += 1
                logger.warning('Ignoring violation %s in %s:%d', violation.name, record.file, record.line)
            return

        self.counters[violation] += 1
        if self.max_infraction < level:
            self.max_infraction = level

        if len(records) > 1:
            source_files = ''
            source = '%s'
        else:
            source_files = ' '.join('{file}:{line}'.format(file=record.file, line=record.line) for record in records)
            source = ' (defined in %s)'
        self.logger.log(level, '%s ' + message + source, violation, *args, source_files)

    def _setup_logger(self):
        """Setup the violations logger, streams to stdout."""
        self.logger.propagate = False
        self.logger.raiseExceptions = False

        formatter = logging.Formatter(fmt='%(message)s')
        handler = logging.StreamHandler(stream=sys.stdout)
        handler.setFormatter(formatter)
        handler.setLevel(self.level)
        self.logger.addHandler(handler)

    # ERRORS

    def e_global_duplicate(self, records):
        self._err(records, 'Global duplicate records found: %s', records)

    def e_missing_or_wrong_ip_for_name_and_ptr(self, record, ips):
        self._err([record], "Missing IPv%d '%s' for name '%s' and PTR '%s'. Current IPs are: %s",
                  record.ip.version, record.ip, record.name, record.key, ips)

    def e_missing_or_wrong_ptr_for_name_and_ip(self, ptr, name, ip, ptrs, records):
        self._err(records, "Missing PTR '%s' for name '%s' and IP '%s', PTRs are: %s",
                  ptr, name, ip, ptrs)

    def e_multiple_ips_for_name(self, name, records):
        self._err(records, "Found %d IPs for name '%s', expected 1: %s",
                  len(records), name, records)

    def e_too_many_mgmt_names(self, label, value, records):
        self._err(records, "Found %d name(s) for %s '%s', expected 2 (hostname, wmfNNNN): %s",
                  len(records), label, value, records)

    def e_too_many_names(self, label, value, records):
        self._err(records, "Found %d name(s) for %s '%s', expected 1: %s",
                  len(records), label, value, records)

    def e_multiple_asset_tags(self, label, value, records):
        self._err(records, "Multiple asset tags found for %s '%s': %s", label, value, records)

    def e_missing_ganeti_comment(self, name, records):
        self._err(records, "Missing ganeti comment for name '%s' in record(s): %s", name, records)

    # WARNINGS

    def w_missing_ip_for_name_and_ptr(self, record):
        self._warn([record], "Missing IPv%d '%s' for name '%s' and PTR '%s'. No current IP set.",
                   record.ip.version, record.ip, record.name, record.key)

    def w_missing_ptr_for_name_and_ip(self, ptr, name, ip, ptrs, records):
        self._warn(records, "Missing PTR '%s' for name '%s' and IP '%s', PTRs are: %s",
                   ptr, name, ip, ptrs)

    def w_missing_asset_tag(self, label, value, records):
        names = ' '.join(record.name for record in records)
        self._warn(records, "Missing asset tag for %s '%s' and name(s) '%s'", label, value, names)

    def w_missing_dual_stack_for_name(self, name, records):
        self._warn(records, "Found %d IP(s) for name '%s' but expected dual stack (IPv4 + IPv6): %s",
                   len(records), name, records)

    def w_missing_mgmt_for_name(self, name, records):
        self._warn(records, "Missing mgmt record for name '%s' and record(s): %s", name, records)

    def w_too_few_mgmt_names(self, label, value, records):
        self._warn(records, "Found %d name(s) for %s '%s', expected 2 (hostname, wmfNNNN): %s",
                   len(records), label, value, records)

    def w_too_many_public_names(self, label, value, records):
        self._warn(records, "Found %d name(s) for %s '%s', expected 1: %s",
                   len(records), label, value, records)


class PrintList(list):
    """Custom list class to pretty print the results, one per line, indented."""

    def __str__(self):
        """Define a specific string representation, calling str() on the lists's items."""
        if len(self):
            return '\n    ' + '\n    '.join(str(item) for item in self)
        else:
            return '[]'


class DNSRecord:
    """A DNS Record object, immutable."""
    # Specify the fields that can be set, also optimizing them.
    __slots__ = ['key', 'type', 'value', 'file', 'line', 'comment', 'name', 'ip', 'is_ganeti']

    def __init__(self, key, record_type, value, file, line, comment=''):
        """Constructor of as DNSRecord object."""
        if record_type in ('A', 'AAAA'):
            name = key
            ip = ipaddress.ip_address(value)
            if (record_type == 'A' and ip.version != 4) or (record_type == 'AAAA' and ip.version != 6):
                raise ValueError("Invalid IPv{ver} value '{ip}' for record {type}: {name}".format(
                    ver=ip.version, ip=ip, type=record_type, name=name))

        elif record_type == 'PTR':
            name = value
            # Reverse the PTR back to IP
            reverse = key.split('.')[:-3][::-1]
            if key.endswith(IPV6_REVERSE_DOMAIN):
                addr = ':'.join(''.join(reverse[i:i+4]) for i in range(0, 32, 4))
            elif key.endswith(IPV4_REVERSE_DOMAIN):
                addr = '.'.join(reverse)
            else:
                raise ValueError('Unknown PTR type: {pointer}'.format(pointer=key))

            ip = ipaddress.ip_address(addr)
        else:
            raise ValueError('Unrecognized record type: {type}', type=record_type)

        # Use object's __setattr__ to bypass the its own __setattr__.
        object.__setattr__(self, 'key', key)
        object.__setattr__(self, 'type', record_type)
        object.__setattr__(self, 'value', value)
        object.__setattr__(self, 'file', file)
        object.__setattr__(self, 'line', line)
        object.__setattr__(self, 'comment', comment)
        object.__setattr__(self, 'name', name)
        object.__setattr__(self, 'ip', ip)
        object.__setattr__(self, 'is_ganeti', 'VM on ganeti' in comment)

    def __setattr__(self, *args):
        """Do not allow to modify existing attributes."""
        raise AttributeError("can't set attribute")

    def __delattr__(self, *args):
        """Do not allow to delete existing attributes."""
        raise AttributeError("can't delete attribute")

    def __repr__(self):
        """Representation of the object."""
        return '<DNSRecord {o.key} {o.type} {o.value} ({o.file}:{o.line}) {o.comment}>'.format(o=self)

    def __str__(self):
        """String representation of the object."""
        return '{o.file}:{o.line} {o.key} {o.type} {o.value} {o.comment}'.format(o=self)

    def __hash__(self):
        """Make the class hashable based only on the DNS-meaningful part of the data."""
        return hash((self.key, self.type, self.value))

    def __eq__(self, other):
        """Equality comparison operator, required to use instances as dictionary keys."""
        if type(other) != DNSRecord:
            return False

        return self.key == other.key and self.type == other.type and self.value == other.value


class ZonesValidator:
    """Zones Validator main class."""

    def __init__(self, zonefiles, reporter):
        """Constructor, initialize variables and reporter logger."""
        self.zonefiles = zonefiles

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
        self.skipped_origins = 0
        self.skipped_records = 0

        self.reporter = reporter

    def validate(self):
        """Parse all the configured zonfiles and validate the records."""
        self._parse()

        logger.info(('PARSE STATISTICS | Files:%d, Origins:%d, Domain origins with records:%d, '
                     'Pointer origins with records:%d, Skipped origins:%d, IPs:%d, PTRs:%d, '
                     'Names from direct records:%d, Names from pointer records:%d, Skipped records:%d'),
                    len(self.zonefiles),
                    len(self.origins),
                    len(self.names['IP']),
                    len(self.names['PTR']),
                    self.skipped_origins,
                    sum(len(ips) for ips in self.names['IP'].values()),
                    sum(len(ptrs) for ptrs in self.names['PTR'].values()),
                    sum(len(ips) for ips in self.ips.values()),
                    sum(len(ptrs) for ptrs in self.ptrs.values()),
                    self.skipped_records)

        self._validate()

    @staticmethod
    def is_mgmt_subhost(name):
        """Return True if the record has more than 4 levels.

        Example: <subrecord>.<record>.mgmt.<dc>.wmnet.
        """
        return len(name.split('.')) > 5  # All names have the tailing dot

    def _parse(self):
        """Parse all the configured zonefiles."""
        for zonefile in self.zonefiles:
            logger.debug('Parsing zonefile %s', zonefile)
            self.zone = os.path.basename(zonefile)
            # Until the first $ORIGIN line the filename itself is the $ORIGIN value
            self.origin = self.zone + '.'
            self.origins.add(self.origin)

            with open(zonefile, 'r') as f:
                for lineno, line in enumerate(f.readlines(), start=1):
                    self._process_line(line, lineno)
                    if not line.startswith(' '):
                        self.previous_full_line = line

    def _process_line(self, line, lineno):
        """Process a zone file line."""
        stripped_line = line.strip()
        if not line or not stripped_line or line[0] == ';' or stripped_line[0] == ';':
            return  # Empty line or comment

        elif line.startswith('$ORIGIN '):
            self.origin = line.replace('@Z', self.zone + '.').split()[1]
            if self.origin[-1] != '.':
                raise ValueError(
                    'Unsupported not fully qualified $ORIGIN: {file}:{lineno} {line}'.format(
                        file=self.zone, lineno=lineno, line=line))

            self.origins.add(self.origin)

        elif self.origin is not None and self.origin.startswith('svc.'):
            self.skipped_origins += 1
            logger.debug('Skip svc.* $ORIGIN %s', self.origin)
            return

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

            self.unique_records[fqdn].append(record)
            self.names['IP'][self.origin][ip].append(record)
            self.ips[self.origin][fqdn].append(record)
            if self._is_mgmt(self.origin):
                self.fqdn_mgmt_prefixes.add('.'.join(fqdn.split('.')[:2]))

        elif ' IN PTR ' in line:
            ip, _, _, record_type, fqdn, *comments = line.split(None, 5)
            if '.svc.' in fqdn:
                self.skipped_records += 1
                logger.debug('Skip .svc. record %s', fqdn)
                return

            if ip[-1] == '.':
                raise ValueError('Unsupported fully qualified PTR: {file}:{lineno} {line}'.format(
                    file=self.zone, lineno=lineno, line=line))

            if fqdn[-1] != '.':
                raise ValueError('Unsupported not fully qualified PTR pointer: {file}:{lineno} {line}'.format(
                    file=self.zone, lineno=lineno, line=line))

            ptr = '.'.join([ip, self.origin])
            comment = comments[0].strip() if comments else ''
            record = DNSRecord(ptr, record_type, fqdn, self.zone, lineno, comment=comment)

            self.unique_records[fqdn].append(record)
            self.names['PTR'][self.origin][ptr].append(record)
            self.ptrs[self.origin][fqdn].append(record)
            if '.mgmt.' in fqdn:
                self.fqdn_mgmt_prefixes.add('.'.join(fqdn.split('.')[:2]))

    def _validate(self):
        """Validate all the parsed records."""
        self._find_duplicates()
        self._validate_ganeti_comments()

        for origin in sorted(self.origins):
            is_mgmt = self._is_mgmt(origin)
            logger.debug('Validating $ORIGIN %s (is_mgmt=%s)', origin, is_mgmt)
            self._validate_origin_names(origin, is_mgmt)
            self._validate_origin_ips(origin, is_mgmt)
            self._validate_origin_ptrs(origin, is_mgmt)

    def _find_duplicates(self):
        """Find all global duplicate records."""
        for records in self.unique_records.values():
            duplicates = [record for record in records if records.count(record) > 1]
            for duplicate in duplicates:
                self.reporter.e_global_duplicate(duplicates)

    def _validate_ganeti_comments(self):
        """Check if any Ganeti comments are missing."""
        for name, records in self.unique_records.items():
            missing = PrintList(record for record in records if not record.is_ganeti)
            if missing == records or not missing:  # Either not a Ganeti instance or all comments are there
                continue

            self.reporter.e_missing_ganeti_comment(name, missing)

    def _validate_origin_names(self, origin, is_mgmt):
        """Validate IPs and PTRs in the given origin."""
        for label, names in sorted(self.names.items()):
            for value, records in sorted(names[origin].items()):
                if is_mgmt:
                    self._validate_mgmt_names(origin, value, records, label)
                else:
                    self._validate_names(value, records, label)

    def _validate_mgmt_names(self, origin, ip, records, label):
        """Validate all the mgmt names for the given IP/PTR, expecting two entries."""
        if len(records) == 1:  # Check if for this item it's ok to have only one entry.
            name = records[0].name
            if ZonesValidator.is_mgmt_subhost(name):
                logger.debug('Ignoring 5th level mgmt record: %s', records[0])
                return
            if any(name.startswith(prefix) for prefix in NO_ASSET_TAG_PREFIXES):
                logger.debug('Ignoring no asset tag mgmt record: %s', records[0])
                return

        if len(records) != 2:  # We expected 2 records for each mgmt, hostname and WMF asset tag.
            if len(records) > 2:
                self.reporter.e_too_many_mgmt_names(label, ip, records)
            else:
                self.reporter.w_too_few_mgmt_names(label, ip, records)

        # Check that there is one and only one WMF asset tag set for this name.
        matches = [ASSET_TAG_PATTERN.match(record.name) for record in records]
        if all(match is None for match in matches):
            self.reporter.w_missing_asset_tag(label, ip, records)
        elif sum(match is not None for match in matches) > 1:
            self.reporter.e_multiple_asset_tags(label, ip, records)

    def _validate_names(self, value, records, label):
        """Validate record names for all the given IP/PTR, only one record expected."""
        if len(records) != 1:
            if any(record.ip.is_private for record in records):
                self.reporter.e_too_many_names(label, value, records)
            else:
                self.reporter.w_too_many_public_names(label, value, records)

    def _validate_origin_ips(self, origin, is_mgmt):
        """Validate PTRs for all the IPs in the given origin."""
        for name, records in sorted(self.ips[origin].items()):
            if not records:
                continue

            self._validate_mgmt_exists(name, records, is_mgmt)
            self._validate_ips(origin, name, records, is_mgmt)
            self._validate_ips_ptrs(origin, name, records, is_mgmt)

    def _validate_origin_ptrs(self, origin, is_mgmt):
        """Validate IPs for all the PTRs in the given origin."""
        is_v6 = IPV6_REVERSE_DOMAIN in origin
        for name, records in sorted(self.ptrs[origin].items()):
            if not records:
                continue

            self._validate_ptrs_ips(origin, name, records, is_mgmt)
            if not is_v6:  # The management network is IPv4 only.
                self._validate_mgmt_exists(name, records, is_mgmt)

    def _validate_ips(self, origin, name, records, is_mgmt):
        """Validate the IPs for the given record name."""
        if len(records) == 2 and not is_mgmt:  # Two records, must be one IPv4 and one IPv6
            if sum(record.ip.version for record in records) != 10:
                self.reporter.w_missing_dual_stack_for_name(name, records)
        elif len(records) != 1:
            self.reporter.e_multiple_ips_for_name(name, records)

    def _validate_ips_ptrs(self, origin, name, records, is_mgmt):
        """Validate the PTR records of all the IPs."""
        if is_mgmt and ZonesValidator.is_mgmt_subhost(name):
            logger.debug('Skipping 5th level mgmt name %s', name)
            return

        ptrs = []
        for orig in self.origins:
            if name in self.ptrs[orig]:
                ptrs += [record.key for record in self.ptrs[orig][name]]

        for record in records:
            ptr = record.ip.reverse_pointer + '.'
            if ptrs:
                if ptr not in ptrs:
                    self.reporter.e_missing_or_wrong_ptr_for_name_and_ip(ptr, name, record.value, ptrs, records)
            else:
                self.reporter.w_missing_ptr_for_name_and_ip(ptr, name, record.value, ptrs, records)

    def _validate_ptrs_ips(self, origin, name, records, is_mgmt):
        """Validate the IP records of all the PTRs."""
        if is_mgmt and ZonesValidator.is_mgmt_subhost(name):
            logger.debug('Skipping 5th level mgmt name %s', name)
            return

        ips = []
        for orig in self.origins:
            if name in self.ips[orig]:
                ips += [record.value for record in self.ips[orig][name]]

        for record in records:
            try:
                if str(record.ip) not in ips:
                    if ips:
                        self.reporter.e_missing_or_wrong_ip_for_name_and_ptr(record, ips)
                    else:
                        self.reporter.w_missing_ip_for_name_and_ptr(record)
            except ValueError as e:
                raise ValueError("Unable to reverse PTR to IP for record %s: %s", record, e)

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

        ganeti = [record for record in records if record.is_ganeti]
        if not ganeti:
            self.reporter.w_missing_mgmt_for_name(name, records)

        elif len(ganeti) < len(records):
            missing = PrintList([record for record in records if record not in ganeti])
            self.reporter.e_missing_ganeti_comment(name, missing)

    def _is_mgmt(self, origin):
        """Return True if the given origin is a management one."""
        if origin.startswith('mgmt.'):
            return True

        if not origin.endswith(IPV4_REVERSE_DOMAIN):
            return False

        # Detect if it's a mgmt reverse ORIGIN by checking if there is any mgmt item
        if any(name.split('.')[-4] == 'mgmt' for name in self.ptrs[origin].keys()):
            return True

        return False


def parse_args():
    """Parse command line arguments."""
    errors_string = ', '.join([v.name for v in Error])
    warnings_string = ', '.join([v.name for v in Warning])

    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-z', '--zones_dir', required=True,
                        help=('Directory containing generated zonefiles, required'))
    parser.add_argument('-e', '--errors', action='store_true',
                        help=('Set the report level to errors, reporting error details. '
                              'By default only the summary is reported.'))
    parser.add_argument('-w', '--warnings', action='store_true',
                        help=('Set the report level to warnings, reporting both error and warning details. '
                              'By default only the summary is reported.'))
    vgroup = parser.add_mutually_exclusive_group()
    vgroup.add_argument('-i', '--ignores',
                        help=('Comma-separated list of violations to ignore (case insensitive). Available errors: '
                              '{errors} ---- Available warnings: {warnings}').format(
                            errors=errors_string, warnings=warnings_string))
    vgroup.add_argument('-s', '--show-only', help=('Comma-separated list of violations to show (case insensitive). '
                                                   'See -i/--ignores for the available violations.'))
    sgroup = parser.add_mutually_exclusive_group()
    sgroup.add_argument('--save', type=argparse.FileType('w'), metavar='SAVE_PATH',
                        help=('Save the summary of violations to the given path in JSON format. To be used later by '
                              'the --compare option.'))
    sgroup.add_argument('--compare', type=argparse.FileType(), metavar='READ_PATH',
                        help=('Compare the summary of violations with the given path generated by a previous run with '
                              'the --save option. Fail if any new error or warning is reported.'))
    parser.add_argument('-d', '--debug', action='store_true', help='Set log level to debug.')

    args = parser.parse_args()

    try:
        if args.ignores is not None:
            args.ignores = [ViolationFactory.find(name) for name in args.ignores.upper().split(',')]

        if args.show_only is not None:
            args.show_only = [ViolationFactory.find(name) for name in args.show_only.upper().split(',')]
    except ValueError as e:
        parser.error(e)

    return args


def compare_violations(previous, current):
    """Compare the summary of two different runs.

    Arguments:
        previous (dict): the previous violations.
        current (dict): the current violations.

    Returns:
        int: the return code to use, 0 if no new violations were introducted, 1 otherwise.

    """
    retcode = 0
    for violation, count in current.items():
        prev_count = previous.get(violation, 0)
        if count > prev_count:
            logger.error('%d new violations of type %s introduced', (count - prev_count), violation)
            retcode = 1
        elif count < prev_count:
            logger.info('%d violations of type %s removed', (prev_count - count), violation)

    missing_keys = [key for key in previous.keys() if key not in current]
    for missing in missing_keys:
        logger.info('All violations (%d) of type %s removed', previous[missing], missing)

    if not retcode:
        logger.info('No new violation introduced')

    return retcode


def main():
    """Run the script."""
    args = parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)

    level = logging.CRITICAL
    if args.warnings or args.show_only is not None:
        level = logging.WARNING
    elif args.errors:
        level = logging.ERROR

    # Collect all the zonefiles
    base_path = os.path.abspath(args.zones_dir)
    zonefiles = [os.path.join(base_path, zone) for zone in ('wmnet', 'wikimedia.org')]  # Default zones
    zonefiles += glob.glob(os.path.join(base_path, '*.in-addr.arpa'))  # IPv4 reverse zonefiles
    zonefiles += glob.glob(os.path.join(base_path, '*.ip6.arpa'))  # IPv6 reverse zonefiles

    reporter = ViolationsReporter(level, ignores=args.ignores, shows=args.show_only)
    validator = ZonesValidator(zonefiles, reporter)
    validator.validate()
    violations = reporter.log_results()

    if args.save:
        json.dump(violations, args.save)

    if args.compare is not None:
        return compare_violations(json.load(args.compare), violations)

    # The return code depends on the maximum level of logged message in the checks report logger
    if reporter.max_infraction >= logging.ERROR:
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
