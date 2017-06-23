#!/usr/bin/env python
#
# Given a DNS zone name, this script queries all the authoritative
# servers for the zone for their SOA record, and prints a line for
# each one with their SOA serial#. This provides a quick way to
# visually scan the output to determine if the serial numbers are in
# sync or not, and if not, by how much.
# Optional command line arguments can be used to specify additional
# servers to query (e.g. hidden masters, unadvertised secondaries etc),
# or to restrict the queries to only the IPv4 or IPv6 addresses of the
# servers.
#
# The exit status of the program is 0 if all serial numbers are
# successfully obtained and are identical, and 1 otherwise.
#
# Author: Shumon Huque <shuque@gmail.com>
#
# Sample output:
#
#$ ./check_serial.py upenn.edu
#     1006020744 adns3.upenn.edu. 2607:f470:1003::3:c
#     1006020744 adns3.upenn.edu. 128.91.251.33
#     1006020744 adns2.upenn.edu. 2607:f470:1002::2:3
#     1006020744 adns2.upenn.edu. 128.91.254.22
#     1006020744 dns2.udel.edu. 128.175.13.17
#     1006020744 sns-pb.isc.org. 2001:500:2e::1
#     1006020744 sns-pb.isc.org. 192.5.4.1
#     1006020744 adns1.upenn.edu. 2607:f470:1001::1:a
#     1006020744 adns1.upenn.edu. 128.91.3.128
#     1006020744 dns1.udel.edu. 128.175.13.16
#

import os, sys, socket
import dns.resolver
import dns.message, dns.query, dns.rdatatype, dns.rcode
import getopt

TIMEOUT = 10
RETRIES = 5
AF_DEFAULT = socket.AF_UNSPEC          # v4=AF_INET, v6=AF_INET6
AF_TEXT = {
    socket.AF_UNSPEC : "Unspec",
    socket.AF_INET : "IPv4",
    socket.AF_INET6 : "IPv6",
    }


def send_query_udp(qname, qtype, ip, timeout=TIMEOUT, retries=RETRIES):
    gotresponse = False
    res = None
    msg = dns.message.make_query(qname, qtype)
    while (not gotresponse and (retries > 0)):
        retries -= 1
        try:
            res = dns.query.udp(msg, ip, timeout=timeout)
            gotresponse = True
        except dns.exception.Timeout:
            pass
    return res


def get_serial(zone, nshost, nsip):
    serial = None
    resp = send_query_udp(zone, 'SOA', nsip)
    if resp == None:
        print("ERROR: No answer from %s %s" % (nshost, nsip))
    elif resp.rcode() != 0:
        print("ERROR: %s %s rcode %d" % (nshost, nsip, resp.rcode()))
    else:
        if len(resp.answer) != 1:
            print("Error: %s %s: more than 1 answer found for SOA" % \
                  (nshost, nsip))
        else:
            soa_rdata = resp.answer[0].items[0]
            serial = soa_rdata.serial
    return serial


def get_ip(nsname, af=AF_DEFAULT):
    nsip_list = []
    try:
        ai_list = socket.getaddrinfo(nsname, 53, af, socket.SOCK_DGRAM)
    except socket.gaierror:
        j = sys.stderr.write("WARNING: getaddrinfo(%s): %s failed" % \
                             (nsname, AF_TEXT[af]))
    else:
        for (family, socktype, proto, canon, sockaddr) in ai_list:
            nsip_list.append(sockaddr[0])
    return nsip_list


def usage():
    print("""\
Usage: check_soa [-4] [-6] [-a ns1,ns2,..] <zone>

       -4          Use IPv4 transport only
       -6          Use IPv6 transport only
       -a ns1,..   Specify additional nameserver names to query
""")
    sys.exit(1)


if __name__ == '__main__':

    try:
        (options, args) = getopt.getopt(sys.argv[1:], '46a:')
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
        elif opt == "-a":
            ADDITIONAL = optval.split(',')


    ZONE = args[0]
    answers = dns.resolver.query(ZONE, 'NS', 'IN')

    first = True
    firstSerial = None
    rc = 0
    nsname_list = sorted(ADDITIONAL + [str(x.target) for x in answers.rrset])
    for nsname in nsname_list:
        nsip_list = get_ip(nsname, af)
        for nsip in nsip_list:
            serial = get_serial(ZONE, nsname, nsip)
            if serial is None:
                rc = 1
            else:
                if first and rc == 0:
                    firstSerial = serial
                    first = False
                elif rc == 0:
                    if serial != firstSerial:
                        rc = 1
                print("%15ld %s %s" % (serial, nsname, nsip))

    sys.exit(rc)
