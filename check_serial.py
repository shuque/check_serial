#!/usr/bin/env python
#

"""
check_serial.py

Given a DNS zone name, this script queries all the authoritative
servers for the zone for their SOA record, and prints a line for
each one with their SOA serial#, hostname, and IP address.

Author: Shumon Huque <shuque@gmail.com>
"""

import os, sys, socket
import dns.resolver
import dns.message, dns.query, dns.rdatatype, dns.rcode, dns.rdatatype, dns.flags
import getopt

PROGNAME = os.path.basename(sys.argv[0])
TIMEOUT = 5                            # Timeout for each SOA query
RETRIES = 5                            # Max #SOA queries to try per server
ALLOWED_DRIFT = 0                      # Allowed difference in serial numbers
                                       # before we set an error flag.
WANT_DNSSEC = False                    # Use -z to make this True
NO_NSSET = False                       # Query official NS set (-n to negate)
MASTER_IP = None                       # Master server to compare serials with

AF_DEFAULT = socket.AF_UNSPEC          # v4=AF_INET, v6=AF_INET6
AF_TEXT = {
    socket.AF_UNSPEC : "Unspec",
    socket.AF_INET : "IPv4",
    socket.AF_INET6 : "IPv6",
    }


def is_authoritative(msg):
    """Does DNS message have Authoritative Answer (AA) flag set?"""
    return (msg.flags & dns.flags.AA == dns.flags.AA)


def is_truncated(msg):
    """Does DNS message have truncated (TC) flag set?"""
    return (msg.flags & dns.flags.TC == dns.flags.TC)


def send_query_tcp(msg, ip, timeout=TIMEOUT):
    res = None
    try:
        res = dns.query.tcp(msg, ip, timeout=timeout)
    except dns.exception.Timeout:
        print("WARN: TCP query timeout for {}".format(ip))
        pass
    return res


def send_query_udp(msg, ip, timeout=TIMEOUT, retries=RETRIES):
    gotresponse = False
    res = None
    while (not gotresponse and (retries > 0)):
        retries -= 1
        try:
            res = dns.query.udp(msg, ip, timeout=timeout)
            gotresponse = True
        except dns.exception.Timeout:
            print("WARN: UDP query timeout for {}".format(ip))
            pass
    return res


def send_query(qname, qtype, ip, timeout=TIMEOUT, retries=RETRIES):
    res = None
    msg = dns.message.make_query(qname, qtype, want_dnssec=WANT_DNSSEC)
    msg.flags &= ~dns.flags.RD  # set RD=0
    res = send_query_udp(msg, ip)
    if res and is_truncated(res):
        print("WARN: response was truncated; retrying with TCP ..")
        res = send_query_tcp(msg, ip)
    return res


def get_serial(zone, nshost, nsip):
    serial = None
    resp = send_query(zone, 'SOA', nsip)
    if resp == None:
        print("ERROR: No answer from %s %s" % (nshost, nsip))
    elif resp.rcode() != 0:
        print("ERROR: %s %s rcode %d" % (nshost, nsip, resp.rcode()))
    elif not is_authoritative(resp):
        print("ERROR: %s %s answer not authoritative" % (nshost, nsip))
    elif is_truncated(resp):
        print("ERROR: %s %s answer is truncated" % (nshost, nsip))
    else:
        for rrset in resp.answer:
            if rrset.rdtype == dns.rdatatype.SOA:
                serial = rrset[0].serial
                break
        else:
            print("ERROR: %s %s: SOA record not found." % (nshost, nsip))
    return serial


def print_info(serial, serialMaster, nsname, nsip, masterip):
    if masterip:
        drift = serialMaster - serial
        if (nsip == masterip):
            print("%15ld [%9s] %s %s" % (serial, "MASTER", nsname, nsip))
        else:
            print("%15ld [%9d] %s %s" % (serial, drift, nsname, nsip))
    else:
        print("%15ld %s %s" % (serial, nsname, nsip))
    return


def get_ip(nsname, af=AF_DEFAULT):
    nsip_list = []
    try:
        ai_list = socket.getaddrinfo(nsname, 53, af, socket.SOCK_DGRAM)
    except socket.gaierror:
        _ = sys.stderr.write("WARNING: getaddrinfo(%s): %s failed\n" % \
                             (nsname, AF_TEXT[af]))
    else:
        for (family, socktype, proto, canon, sockaddr) in ai_list:
            nsip_list.append(sockaddr[0])
    return nsip_list


def usage():
    print("""\
Usage: {} [Options] <zone>

       Options:
       -4          Use IPv4 transport only
       -6          Use IPv6 transport only
       -r N        Maximum # SOA query retries for each server (default {})
       -d N        Allowed SOA serial number drift (default {})
       -m ns       Master server name/address to compare serial numbers with
       -a ns1,..   Specify additional nameserver names/addresses to query
       -z          Set DNSSEC-OK flag in queries (doesn't authenticate yet)
       -n          Don't query advertised nameservers for the zone
""".format(PROGNAME, RETRIES, ALLOWED_DRIFT))
    sys.exit(1)


if __name__ == '__main__':

    try:
        (options, args) = getopt.getopt(sys.argv[1:], '46r:d:m:a:zn')
    except getopt.GetoptError:
        usage()
    if len(args) != 1:
        usage()

    ADDITIONAL = []               # additional (hidden?) NS names to check

    af = AF_DEFAULT
    for (opt, optval) in options:
        if opt == "-4":
            af = socket.AF_INET
        elif opt == "-6":
            af = socket.AF_INET6
        elif opt == "-z":
            WANT_DNSSEC = True
        elif opt == "-n":
            NO_NSSET = True
        elif opt == "-r":
            RETRIES = int(optval)
        elif opt == "-d":
            ALLOWED_DRIFT = int(optval)
        elif opt == "-m":
            MASTER_IP = get_ip(optval, af)[0]
        elif opt == "-a":
            ADDITIONAL = optval.split(',')

    if NO_NSSET and (not ADDITIONAL):
        print("ERROR: -n requires specifying -a")
        usage()

    ZONE = args[0]
    if not NO_NSSET:
        answers = dns.resolver.query(ZONE, 'NS', 'IN')

    serialMaster = None
    serialList = []
    cnt_nsip = 0

    if MASTER_IP:
        cnt_nsip += 1
        serialMaster = get_serial(ZONE, MASTER_IP, MASTER_IP)
        serialList.append(serialMaster)
        print_info(serialMaster, serialMaster, MASTER_IP, MASTER_IP, MASTER_IP)

    if NO_NSSET:
        nsname_list = ADDITIONAL
    else:
        nsname_list = ADDITIONAL + sorted([str(x.target) for x in answers.rrset])

    for nsname in nsname_list:
        nsip_list = get_ip(nsname, af)
        for nsip in nsip_list:
            cnt_nsip += 1
            serial = get_serial(ZONE, nsname, nsip)
            if serial is not None:
                serialList.append(serial)
                print_info(serial, serialMaster, nsname, nsip, MASTER_IP)

    if cnt_nsip != len(serialList):
        rc = 2
    elif serialList.count(serialList[0]) == len(serialList):
        rc = 0
    else:
        serialRange = max(serialList) - min(serialList)
        if serialRange > ALLOWED_DRIFT:
            rc = 1
        else:
            rc = 0

    sys.exit(rc)
