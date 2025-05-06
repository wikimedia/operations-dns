#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

r"""Generates HTTPS Resource Records (TYPE65) in DNS wire format.

This script generates HTTPS Resource Records as per RFC 9460 in DNS wire
format, for gdnsd zone files. It was primarily written to support RDATA
generation for ECH records, but it now supports additional service parameters
like ALPN, port, and v4 and v6 addresses.

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

$ ./utils/type65.py -p 16 -t foo.example.com. --params 'port=53'
Arguments: {'priority': 16, 'target': 'foo.example.com.', 'params': 'port=53'}
IN TYPE65    \# 25 001003666f6f076578616d706c6503636f6d00000300020035
"""

import argparse
import base64
import binascii
import doctest
import enum
import ipaddress
import sys
import typing


class SvcParamKeys(enum.IntEnum):
    """SvcParamKeys as defined in Section 14.3.2 of RFC 9460.

    Support for the following will be added later:
        MANDATORY = 0
        NO_DEFAULT_ALPN = 2
    """
    ALPN = 1
    PORT = 3
    IPV4HINT = 4
    ECH = 5
    IPV6HINT = 6


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


def to_wire(value: typing.Union[int, str], octet: int = 2) -> str:
    """Returns hex representation of an int or string.

    Default: Section 2.2: 2-octet field for int (priority), in network byte order.

    ALPN and others use a single octet and that can be passed manually.

    >>> to_wire(16)
    '0010'
    >>> to_wire("wikimedia")
    '77696b696d65646961'
    """
    match value:
        case int():
            return value.to_bytes(octet, byteorder="big").hex()
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


def process_svcparams(svc_params: str) -> typing.Optional[str]:
    """Processes one or multiple SvcParams and formats them in wire format.

    Some of these examples are directly from the RFC.

    >>> process_svcparams("ech=AET+DQBA8gAgACBXWnEYjZqexZMROd9csCwJFMsU3/lT3UTOui4hc" \
                         "WY1EwAEAAEAAQARd2lraW1lZGlhLWVjaC5vcmcAAA==")
    '000500460044fe0d0040f200200020575a71188d9a9ec5931139df5cb02c0914cb14dff953dd4\
4ceba2e2171663513000400010001001177696b696d656469612d6563682e6f72670000'
    >>> process_svcparams("ipv6hint=2001:db8::1,2001:db8::53:1")
    '0006002020010db800000000000000000000000120010db8000000000000000000530001'
    >>> process_svcparams("port=53")
    '000300020035'
    >>> process_svcparams("alpn=h2,h3-19")
    '000100090268320568332d3139'
    >>> process_svcparams("alpn=h2 ipv4hint=192.0.2.1")
    '0001000302683200040004c0000201'
    >>> process_svcparams("alpn=h2,http/1.1")
    '0001000c02683208687474702f312e31'
    """
    params = svc_params.split(" ")

    # No custom key support, so if we don't support a SvcParam, just quit.
    # It's not difficult to do this, it's just that we just don't care about this yet.
    all_svc_params = [svc.name for svc in SvcParamKeys]
    arg_svc_params = [param.split("=")[0].upper() for param in params]
    if not set(arg_svc_params).issubset(all_svc_params):
        sys.exit(f"Only {', '.join(all_svc_params)} keys are supported! We found {', '.join(arg_svc_params)} instead.")

    # Check if there are multiple SvcParams. If yes, per Section 3, "sort by
    # ascending SvcPriority", and process further.
    if len(params) > 1:
        params.sort(key=lambda svc: SvcParamKeys[svc.split("=")[0].upper()].value)

    # This is where we save all SvcParams that we processed, to calculate the
    # length for the wire format at the end.
    processed_param = []
    for param in params:
        try:
            key, value = param.split("=", 1)
        except ValueError:
            sys.exit(f"Unable to split {params}. Each param should have a key=value pair.")

        key_wire = to_wire(SvcParamKeys[key.upper()].value)
        # This is common to all SvcParamKeys, so append at the start. Mapping
        # defined in the RFC and enumerated in SvcParamKeys.
        processed_param.append(key_wire)

        match key:
            case 'alpn':
                # ALPN values are comma-separated so multiple values will be
                # present. Example: alpn=h2,h3.
                # We don't check for the actual ALPN values and that's OK. We
                # could restrict this to h2,http1.1 but we are leaving this
                # unrestricted for now.
                alpns_value = []
                alpns_len = []
                for proto in value.split(","):
                    alpn_proto_value = to_wire(proto)
                    # Single octect, per RFC.
                    alpn_proto_len = to_wire(len(proto), 1)
                    alpns_value .append(f"{alpn_proto_len}{alpn_proto_value}")
                    # We need this to format ALPN in wire format.
                    alpns_len.append(len(proto))
                # For the length calculation, factor in the individual values
                # and also their count.
                # ProtocolName protocol_name_list<2..2^16-1>. RFC 7301.
                alpn_len = to_wire(len(alpns_value) + sum(alpns_len))
                alpns_formatted = "".join(alpns_value)
                processed_param.append(f"{alpn_len}{alpns_formatted}")

            case 'port':
                port_number = to_wire(int(value))
                port_len = to_wire(len(value))
                processed_param.append(f"{port_len}{port_number}")

            case 'ipv4hint' | 'ipv6hint':
                # There can be multiple IP addresses, separated by a comma.
                ips = []
                for ip in value.split(","):
                    ip_value = format(int(ipaddress.ip_address(ip)), "x")
                    ips.append(ip_value)
                ips_len = to_wire(sum([len(ipaddress.ip_address(ip).packed) for ip in value.split(",")]))
                processed_param.append(f"{ips_len}{''.join(ips)}")

            case 'ech':
                # Encodes to base64, per https://datatracker.ietf.org/doc/draft-ietf-tls-svcb-ech/07/
                # Not part of RFC 9460 but as implemented by every
                # implementation, especially the current one we have deployed
                # in T205378.
                try:
                    ech_value = base64.b64decode(value).hex()
                except binascii.Error:
                    sys.exit(f"Error decoding {value}. ECHConfigList should be base64 encoded.")
                ech_len = to_wire(len(bytes.fromhex(ech_value)))
                processed_param.append(f"{ech_len}{ech_value}")

    return "".join(processed_param)


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

    params = process_svcparams(args.params)
    print(wire_result(priority, domain, params))


if __name__ == "__main__":
    doctest.testmod()
    main()
