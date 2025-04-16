#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

r"""Generates HTTPS Resource Records (TYPE65) for ECH keys in DNS wire format.

This script generates HTTPS Resource Records as per RFC 9460 in DNS wire
format, for gdnsd zone files. It currently only supports RDATA generation for
ECH records, though we have plans to add support for other SvcParamKeys such as
ALPN and ip{46}hints.

There is no (intentional) integration with gdnsd; the generated records are
printed on stdout, after which they need to be copied to the relevant zone file
and a TTL needs to be set. A future version of this will directly populate the
zone files, but such a feature is currently not required. SVCB TYPE64 records
are also not supported, though should be easy to extend in theory.

Example Usage:

$ ./utils/type65.py -p 1 -t . --params "ech=test"
Arguments: {'priority': 1, 'target': '.', 'params': 'ech=test'}
IN TYPE65    \# 10 00010000050003b5eb2d

$ ./utils/type65.py -p 0 -t wikimedia.org
Arguments: {'priority': 0, 'target': 'wikimedia.org', 'params': None}
IN TYPE65    \# 16 00000977696b696d65646961036f7267
"""

import argparse
import base64
import binascii
import doctest
import enum
import sys
import typing


class SvcParamKeys(enum.IntEnum):
    """SvcParamKeys as defined in Section 14.3.2 of RFC 9460.

    Support for the following will be added later as required:
        MANDATORY = 0
        ALPN = 1
        NO_DEFAULT_ALPN = 2
        PORT = 3
        IPV4HINT = 4
        IPV6HINT = 6
    """
    ECH = 5


def parse_args() -> argparse.Namespace:
    """Parse args from the command line and sets sane defaults."""
    description = "Generates HTTPS TYPE65 records in RDATA wire format."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-p", "--priority", type=int,
                        default=1,
                        help="service priority. default is 1. priority of 0 indicates Alias mode.")
    parser.add_argument("-t", "--target",
                        default=".",
                        help="target name. default is .")
    parser.add_argument("--params",
                        help="service parameters. this is required if priority is 1.")
    return parser.parse_args()


def to_wire(value: typing.Union[int, str]) -> str:
    """Returns hex representation of an int or string.

    Section 2.2: 2-octet field for int (priority), in network byte order.

    >>> to_wire(16)
    '0010'
    >>> to_wire("wikimedia")
    '77696b696d65646961'
    """
    match value:
        case int():
            return value.to_bytes(2, byteorder="big").hex()
        case str():
            return value.encode().hex()


def domain_to_wire(domain: str) -> str:
    """Converts a domain name to DNS wire format.

    >>> domain_to_wire(".")
    '00'
    >>> domain_to_wire("foo.example.com.")
    '03666f6f076578616d706c6503636f6d00'
    """
    if domain == ".":   # root label
        return "00"
    wire = ""
    for word in domain.split("."):
        wire += len(word).to_bytes(1, byteorder="big").hex() + to_wire(word)
    return wire


def process_svparams(params: str) -> typing.Optional[str]:
    """Processes SvcParams (ECH keys) and formats them in wire format.

    >>> process_svparams("ech=AET+DQBA8gAgACBXWnEYjZqexZMROd9csCwJFMsU3/lT3UTOui4hc" \
                         "WY1EwAEAAEAAQARd2lraW1lZGlhLWVjaC5vcmcAAA==")
    '000500460044fe0d0040f200200020575a71188d9a9ec5931139df5cb02c0914cb14dff953dd4\
4ceba2e2171663513000400010001001177696b696d656469612d6563682e6f72670000'
    """
    # It is fine to assume that a single record just has one (key,value) pair.
    # Split just once once = to get what we need and to avoid issues with
    # base64 padding.
    try:
        key, value = params.split("=", 1)
    except ValueError:
        sys.exit(f"Unable to split {params}. Was a key=value passed to --params?")

    try:
        key_wire = to_wire(SvcParamKeys[key.upper()].value)
    except KeyError:
        sys.exit(f"Only ECH keys are supported! We found {key} instead.")

    try:
        value_decoded = base64.b64decode(value).hex()
    except binascii.Error:
        sys.exit(f"Error decoding {value}. ECHConfigList should be bas64 encoded.")
    value_len = to_wire(len(bytes.fromhex(value_decoded)))

    format_response = f"{key_wire}{value_len}{value_decoded}"
    return format_response


def wire_result(*strings: typing.Any) -> str:
    """Formats a HTTPS resource record for a gdnsd TYPE65 record.

    This also prepends the IN class and DNS record type since those are
    constant and do not depend on the input.

    >>> print(wire_result("00", "01", "02"))
    IN TYPE65    \\# 3 000102
    >>> print(wire_result("0001", "00", "0005000474657374"))
    IN TYPE65    \\# 11 0001000005000474657374
    """
    joined = "".join(strings)
    length = len(bytes.fromhex(joined))
    return rf"IN TYPE65    \# {length} {joined}"


def main() -> None:
    args = parse_args()
    print(f"Arguments: {vars(args)}")

    if args.priority != 0 and not args.params:
        sys.exit(f"Non-zero priority ({args.priority}) set, but no service parameters were passed.")

    priority = to_wire(args.priority)
    domain = domain_to_wire(args.target)

    # No SvcParams in case of AliasMode, so we print the wire format output and quit.
    if args.priority == 0:
        print(wire_result(priority, domain))
        sys.exit(0)

    params = process_svparams(args.params)
    print(wire_result(priority, domain, params))


if __name__ == "__main__":
    doctest.testmod()
    main()
