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
VERSION = "1.1.0"

class Prefs:
    """Configuration Preferences"""
    TIMEOUT = 3                         # Timeout for each SOA query
    RETRIES = 3                         # Max #SOA queries to try per server
    ALLOWED_DRIFT = 0                   # Allowed difference in serial numbers
    USE_TCP = False                     # Use TCP (-c to set to True)
    WANT_DNSSEC = False                 # Use -z to make this True
    NO_NSSET = False                    # Query official NS set (-n to negate)
    MASTER = None                       # Master server name
    MASTER_IP = None                    # Master server IP address
    MASTER_SERIAL = None
    ADDITIONAL = []                     # additional NS names to check
    AF = socket.AF_UNSPEC               # v4=AF_INET, v6=AF_INET6
    NSID = False                        # query for, and print, EDNS0(NSID)


class Stats:
    """Runtime stats"""
    SERIAL_LIST = []
    COUNT_NSIP = 0


AF_TEXT = {
    socket.AF_UNSPEC : "Unspec",
    socket.AF_INET : "IPv4",
    socket.AF_INET6 : "IPv6",
}


def send_query_tcp(msg, ipaddress, timeout=Prefs.TIMEOUT):
    """send DNS query over TCP to given IP address"""
    res = None
    try:
        res = dns.query.tcp(msg, ipaddress, timeout=timeout)
    except dns.exception.Timeout:
        print("WARN: TCP query timeout for {}".format(ipaddress))
    return res


def send_query_udp(msg, ipaddress, timeout=Prefs.TIMEOUT, retries=Prefs.RETRIES):
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
    msg = dns.message.make_query(qname, qtype, want_dnssec=Prefs.WANT_DNSSEC)
    msg.flags &= ~dns.flags.RD  # set RD=0
    if Prefs.NSID:
        msg.use_edns(options=[dns.edns.GenericOption(dns.edns.NSID, b'')])
    if Prefs.USE_TCP:
        return send_query_tcp(msg, ipaddress, timeout=Prefs.TIMEOUT)
    res = send_query_udp(msg, ipaddress,
                         timeout=Prefs.TIMEOUT, retries=Prefs.RETRIES)
    if res and (res.flags & dns.flags.TC):
        print("WARN: response was truncated; retrying with TCP ..")
        return send_query_tcp(msg, ipaddress, timeout=Prefs.TIMEOUT)
    return res


def get_serial(zone, nshost, nsip):
    """get serial number of zone from given nameserver ip address"""
    serial = None
    nsid = None
    try:
        resp = send_query(zone, 'SOA', nsip)
    except socket.error as e_info:
        print("ERROR: {} {}: socket: {}".format(nshost, nsip, e_info))
        return None, None
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
    if Prefs.NSID:
        for opt in resp.options:
            if opt.otype == dns.edns.NSID:
                nsid = opt.nsid
    return serial, nsid


def print_info(serial, master_serial, nsname, nsid, nsip, masterip):
    """Print serial number info for specified zone and server"""
    if Prefs.NSID:
        if nsid:
            nsid = "(" + nsid.decode("utf-8") + ") "
        else:
            nsid = "() "
    else:
        nsid = ""
    if masterip:
        if (serial is None) or (master_serial is None):
            return
        drift = master_serial - serial
        if nsip == masterip:
            print("{:15d} [{:>9s}] {} {:s}{}".format(serial, "MASTER", nsname, nsid, nsip))
        else:
            print("{:15d} [{:9d}] {} {:s}{}".format(serial, drift, nsname, nsid, nsip))
    else:
        print("{:15d} {} {:s}{}".format(serial, nsname, nsid, nsip))
    return


def get_ip(nsname, address_family=Prefs.AF):
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


def check_all_ns(zone, nsname_list):
    """
    Check all nameserver serials and print information about them.
    Returns the number nameserver IP addresses and the list of
    observed serial numbers.
    """

    for nsname in nsname_list:
        nsip_list = get_ip(nsname, Prefs.AF)
        for nsip in nsip_list:
            Stats.COUNT_NSIP += 1
            serial, nsid = get_serial(zone, nsname, nsip)
            if serial is not None:
                Stats.SERIAL_LIST.append(serial)
                print_info(serial, Prefs.MASTER_SERIAL, nsname, nsid, nsip,
                           Prefs.MASTER_IP)


def check_master(zone):
    """Check master for zone"""

    if Prefs.MASTER:
        Prefs.MASTER_IP = get_ip(Prefs.MASTER, Prefs.AF)[0]
        Stats.COUNT_NSIP += 1
        Prefs.MASTER_SERIAL, nsid = get_serial(zone, Prefs.MASTER, Prefs.MASTER_IP)
        if Prefs.MASTER_SERIAL is None:
            print('ERROR: failed to obtain master serial')
            sys.exit(3)
        Stats.SERIAL_LIST.append(Prefs.MASTER_SERIAL)
        print_info(Prefs.MASTER_SERIAL, Prefs.MASTER_SERIAL,
                   Prefs.MASTER, nsid, Prefs.MASTER_IP, Prefs.MASTER_IP)


def get_nsnames(zone):
    """Get list of nameservers names to query"""

    if Prefs.NO_NSSET:
        if not Prefs.ADDITIONAL:
            print("ERROR: -n requires specifying -a")
            usage()
        return Prefs.ADDITIONAL

    answers = dns.resolver.resolve(zone, 'NS', 'IN')
    return Prefs.ADDITIONAL + sorted([str(x.target) for x in answers.rrset])


def get_exit_code():
    """Calculate exit code"""

    if Stats.COUNT_NSIP != len(Stats.SERIAL_LIST):
        return 2
    if Stats.SERIAL_LIST.count(Stats.SERIAL_LIST[0]) == len(Stats.SERIAL_LIST):
        return 0
    serial_range = max(Stats.SERIAL_LIST) - min(Stats.SERIAL_LIST)
    if serial_range > Prefs.ALLOWED_DRIFT:
        return 1
    return 0


def process_args(arg_vector):
    """Process command line options and arguments"""

    try:
        (options, args) = getopt.getopt(arg_vector, '46ct:r:d:m:a:zni')
    except getopt.GetoptError:
        usage()

    if len(args) != 1:
        usage()

    for (opt, optval) in options:
        if opt == "-4":
            Prefs.AF = socket.AF_INET
        elif opt == "-6":
            Prefs.AF = socket.AF_INET6
        elif opt == "-c":
            Prefs.USE_TCP = True
        elif opt == "-z":
            Prefs.WANT_DNSSEC = True
        elif opt == "-n":
            Prefs.NO_NSSET = True
        elif opt == "-t":
            Prefs.TIMEOUT = int(optval)
        elif opt == "-r":
            Prefs.RETRIES = int(optval)
        elif opt == "-d":
            Prefs.ALLOWED_DRIFT = int(optval)
        elif opt == "-m":
            Prefs.MASTER = optval
        elif opt == "-a":
            Prefs.ADDITIONAL = optval.split(',')
        elif opt == "-i":
            Prefs.NSID = True

    return args[0]


def usage():
    """Print usage string and terminate program."""
    print("""\
{0} version {1}
Usage: {0} [Options] <zone>

       Options:
       -4          Use IPv4 transport only
       -6          Use IPv6 transport only
       -c          Use TCP for queries (default: UDP with TCP on truncation)
       -t N        Query timeout value (default {2} sec)
       -r N        Maximum # SOA query retries for each server (default {3})
       -d N        Allowed SOA serial number drift (default {4})
       -m ns       Master server name/address to compare serial numbers with
       -a ns1,..   Specify additional nameserver names/addresses to query
       -z          Set DNSSEC-OK flag in queries (doesn't authenticate yet)
       -n          Don't query advertised nameservers for the zone
       -i          Query for, and print, each responding server's NSID string
""".format(PROGNAME, VERSION, Prefs.TIMEOUT, Prefs.RETRIES, Prefs.ALLOWED_DRIFT))
    sys.exit(4)


if __name__ == '__main__':

    ZONE = process_args(sys.argv[1:])
    NSNAME_LIST = get_nsnames(ZONE)
    check_master(ZONE)
    check_all_ns(ZONE, NSNAME_LIST)
    sys.exit(get_exit_code())
