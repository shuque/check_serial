# check_serial
Check DNS zone serial numbers

Given a DNS zone name, this script queries all the authoritative
servers for the zone for their SOA record, and prints a line for
each one with their SOA serial#, hostname, and IP address.

Optional command line arguments can be used to specify additional
servers to query (e.g. hidden masters, unadvertised secondaries etc),
explicit master server to compare serial numbers with, to restrict the
queries to only the IPv4 or IPv6 addresses of the servers, to specify
the allowed drift, specify the number of query retries for each server,
and whether to set the DNSSEC-OK flag.

The exit status of the program is:

  0  If serial numbers for every server are identical or do not
     differ by more than ALLOWED_DRIFT (default 0)  
  1  If serial numbers for some servers differ by more than ALLOWED_DRIFT  
  2  If some servers failed to respond.  
  3  If master server (if -m) failed to respond.
  4  On program invocation error.

Author: Shumon Huque <shuque@gmail.com>

Pre-requisites:

   dnspython module ( http://www.dnspython.org/ )

Sample output:

```
$ check_serial.py
check_serial.py version 1.0.0
Usage: check_serial.py [Options] <zone>

       Options:
       -4          Use IPv4 transport only
       -6          Use IPv6 transport only
       -c          Use TCP for queries (default: UDP with TCP on truncation)
       -t N        Query timeout value (default 5 sec)
       -r N        Maximum # SOA query retries for each server (default 5)
       -d N        Allowed SOA serial number drift (default 0)
       -m ns       Master server name/address to compare serial numbers with
       -a ns1,..   Specify additional nameserver names/addresses to query
       -z          Set DNSSEC-OK flag in queries (doesn't authenticate yet)
       -n          Don't query advertised nameservers for the zone

$ check_serial.py upenn.edu
     1006027704 adns1.upenn.edu. 2607:f470:1001::1:a
     1006027704 adns1.upenn.edu. 128.91.3.128
     1006027704 adns2.upenn.edu. 2607:f470:1002::2:3
     1006027704 adns2.upenn.edu. 128.91.254.22
     1006027704 adns3.upenn.edu. 2607:f470:1003::3:c
     1006027704 adns3.upenn.edu. 128.91.251.33
     1006027704 dns1.udel.edu. 128.175.13.16
     1006027704 dns2.udel.edu. 128.175.13.17
     1006027704 sns-pb.isc.org. 2001:500:2e::1
     1006027704 sns-pb.isc.org. 192.5.4.1
$ echo $?
0

$ check_serial.py -m 10.10.10.11 -a 172.17.1.1 example.com
     1002208334 [   MASTER] 10.10.10.11 10.10.10.11
     1002208333 [        1] 172.17.1.1 172.17.1.1
     1002208234 [      100] ns1.example.com. 10.15.1.1
     1002208234 [      100] ns2.example.com. 10.16.1.1
     1002208334 [        0] ns3.example.com. 10.17.1.1
$ echo $?
1
```
