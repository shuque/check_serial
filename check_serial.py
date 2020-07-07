#!/usr/bin/env python3
#

"""
check_serial.py

Given a DNS zone name, this script queries all the authoritative
servers for the zone for their SOA record, and prints a line for
each one with their SOA serial#, hostname, and IP address.

Author: Shumon Huque <shuque@gmail.com>
"""

import os
import sys
import socket
import getopt
import dns.resolver
import dns.message
import dns.query
import dns.rdatatype
import dns.rcode
import dns.flags


PROGNAME = os.path.basename(sys.argv[0])
TIMEOUT = 3                            # Timeout for each SOA query
RETRIES = 3                            # Max #SOA queries to try per server
ALLOWED_DRIFT = 0                      # Allowed difference in serial numbers
                                       # before we set an error flag.
USE_TCP = False                        # Use TCP (-c to set to True)
WANT_DNSSEC = False                    # Use -z to make this True
NO_NSSET = False                       # Query official NS set (-n to negate)
MASTER = None                          # Master server name
MASTER_IP = None                       # Master server to compare serials with
MASTER_SERIAL = None
SERIAL_LIST = []
COUNT_NSIP = 0
ADDITIONAL = []                        # additional (hidden?) NS names to check
AF_DEFAULT = socket.AF_UNSPEC          # v4=AF_INET, v6=AF_INET6

AF_TEXT = {
    socket.AF_UNSPEC : "Unspec",
    socket.AF_INET : "IPv4",
    socket.AF_INET6 : "IPv6",
    }


def send_query_tcp(msg, ipaddress, timeout=TIMEOUT):
    """send DNS query over TCP to given IP address"""
    res = None
    try:
        res = dns.query.tcp(msg, ipaddress, timeout=timeout)
    except dns.exception.Timeout:
        print("WARN: TCP query timeout for {}".format(ipaddress))
    return res


def send_query_udp(msg, ipaddress, timeout=TIMEOUT, retries=RETRIES):
    """send DNS query over UDP to given IP address"""
    gotresponse = False
    res = None
    while (not gotresponse) and (retries > 0):
        retries -= 1
        try:
            res = dns.query.udp(msg, ipaddress, timeout=timeout)
            gotresponse = True
        except dns.exception.Timeout:
            print("WARN: UDP query timeout for {}".format(ipaddress))
    return res


def send_query(qname, qtype, ipaddress):
    """send DNS query to given IP address"""
    res = None
    msg = dns.message.make_query(qname, qtype, want_dnssec=WANT_DNSSEC)
    msg.flags &= ~dns.flags.RD  # set RD=0
    if USE_TCP:
        return send_query_tcp(msg, ipaddress, timeout=TIMEOUT)
    res = send_query_udp(msg, ipaddress, timeout=TIMEOUT, retries=RETRIES)
    if res and (res.flags & dns.flags.TC):
        print("WARN: response was truncated; retrying with TCP ..")
        return send_query_tcp(msg, ipaddress, timeout=TIMEOUT)
    return res


def get_serial(zone, nshost, nsip):
    """get serial number of zone from given nameserver ip address"""
    serial = None
    try:
        resp = send_query(zone, 'SOA', nsip)
    except socket.error as e_info:
        print("ERROR: {} {}: socket: {}".format(nshost, nsip, e_info))
        return None
    if resp is None:
        print("ERROR: No answer from {} {}".format(nshost, nsip))
    elif resp.rcode() != 0:
        print("ERROR: {} {} rcode {}".format(nshost, nsip, resp.rcode()))
    elif not resp.flags & dns.flags.AA:
        print("ERROR: {} {} answer not authoritative".format(nshost, nsip))
    elif resp.flags & dns.flags.TC:
        print("ERROR: {} {} answer is truncated".format(nshost, nsip))
    else:
        for rrset in resp.answer:
            if rrset.rdtype == dns.rdatatype.SOA:
                serial = rrset[0].serial
                break
        else:
            print("ERROR: {} {}: SOA record not found.".format(nshost, nsip))
    return serial


def print_info(serial, master_serial, nsname, nsip, masterip):
    """Print serial number info for specified zone and server"""
    if masterip:
        if (serial is None) or (master_serial is None):
            return
        drift = master_serial - serial
        if nsip == masterip:
            print("{:15d} [{:>9s}] {} {}".format(serial, "MASTER", nsname, nsip))
        else:
            print("{:15d} [{:9d}] {} {}".format(serial, drift, nsname, nsip))
    else:
        print("{:15d} {} {}".format(serial, nsname, nsip))
    return


def get_ip(nsname, address_family=AF_DEFAULT):
    """obtain list of IP addresses for given nameserver name"""
    nsip_list = []
    try:
        ai_list = socket.getaddrinfo(nsname, 53,
                                     address_family, socket.SOCK_DGRAM)
    except socket.gaierror:
        _ = sys.stderr.write("WARNING: getaddrinfo(%s): %s failed\n" % \
                             (nsname, AF_TEXT[address_family]))
    else:
        for (_, _, _, _, sockaddr) in ai_list:
            nsip_list.append(sockaddr[0])
    return nsip_list


def check_all_ns(nsname_list, serial_list, address_family):
    """
    Check all nameserver serials and print information about them.
    Returns the number nameserver IP addresses and the list of
    observed serial numbers.
    """

    count_nsip = 0

    for nsname in nsname_list:
        nsip_list = get_ip(nsname, address_family)
        for nsip in nsip_list:
            count_nsip += 1
            serial = get_serial(ZONE, nsname, nsip)
            if serial is not None:
                serial_list.append(serial)
                print_info(serial, MASTER_SERIAL, nsname, nsip, MASTER_IP)

    return count_nsip


def usage():
    """Print usage string and terminate program."""
    print("""\
Usage: {0} [Options] <zone>

       Options:
       -4          Use IPv4 transport only
       -6          Use IPv6 transport only
       -c          Use TCP for queries (default: UDP with TCP on truncation)
       -t N        Query timeout value (default {1} sec)
       -r N        Maximum # SOA query retries for each server (default {2})
       -d N        Allowed SOA serial number drift (default {3})
       -m ns       Master server name/address to compare serial numbers with
       -a ns1,..   Specify additional nameserver names/addresses to query
       -z          Set DNSSEC-OK flag in queries (doesn't authenticate yet)
       -n          Don't query advertised nameservers for the zone
""".format(PROGNAME, TIMEOUT, RETRIES, ALLOWED_DRIFT))
    sys.exit(1)


if __name__ == '__main__':

    try:
        (OPTIONS, ARGS) = getopt.getopt(sys.argv[1:], '46ct:r:d:m:a:zn')
    except getopt.GetoptError:
        usage()
    if len(ARGS) != 1:
        usage()

    AF = AF_DEFAULT
    for (opt, optval) in OPTIONS:
        if opt == "-4":
            AF = socket.AF_INET
        elif opt == "-6":
            AF = socket.AF_INET6
        elif opt == "-c":
            USE_TCP = True
        elif opt == "-z":
            WANT_DNSSEC = True
        elif opt == "-n":
            NO_NSSET = True
        elif opt == "-t":
            TIMEOUT = int(optval)
        elif opt == "-r":
            RETRIES = int(optval)
        elif opt == "-d":
            ALLOWED_DRIFT = int(optval)
        elif opt == "-m":
            MASTER = optval
        elif opt == "-a":
            ADDITIONAL = optval.split(',')

    ZONE = ARGS[0]

    if NO_NSSET:
        if not ADDITIONAL:
            print("ERROR: -n requires specifying -a")
            usage()
        else:
            NSNAME_LIST = ADDITIONAL
    else:
        ANSWERS = dns.resolver.query(ZONE, 'NS', 'IN')
        NSNAME_LIST = ADDITIONAL + sorted([str(x.target) for x in ANSWERS.rrset])

    if MASTER:
        MASTER_IP = get_ip(MASTER, AF)[0]
        COUNT_NSIP += 1
        MASTER_SERIAL = get_serial(ZONE, MASTER, MASTER_IP)
        if MASTER_SERIAL is None:
            print('ERROR: failed to obtain master serial')
            sys.exit(3)
        SERIAL_LIST.append(MASTER_SERIAL)
        print_info(MASTER_SERIAL, MASTER_SERIAL, MASTER, MASTER_IP, MASTER_IP)

    COUNT_NSIP += check_all_ns(NSNAME_LIST, SERIAL_LIST, AF)

    if COUNT_NSIP != len(SERIAL_LIST):
        RC = 2
    elif SERIAL_LIST.count(SERIAL_LIST[0]) == len(SERIAL_LIST):
        RC = 0
    else:
        SERIALRANGE = max(SERIAL_LIST) - min(SERIAL_LIST)
        if SERIALRANGE > ALLOWED_DRIFT:
            RC = 1
        else:
            RC = 0

    sys.exit(RC)
