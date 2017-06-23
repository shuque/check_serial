# check_serial
Check DNS zone serial numbers

Given a DNS zone name, this script queries all the authoritative
servers for the zone for their SOA record, and prints a line for
each one with their SOA serial#. This provides a quick way to
visually scan the output to determine if the serial numbers are in
sync or not, and if not, by how much.
Optional command line arguments can be used to specify additional
servers to query (e.g. hidden masters, unadvertised secondaries etc),
or to restrict the queries to only the IPv4 or IPv6 addresses of the
servers.

Author: Shumon Huque <shuque@gmail.com>

Sample output:

```
$ ./check_serial.py
Usage: check_soa [-4] [-6] [-r N] [-a ns1,ns2,..] <zone>

       -4          Use IPv4 transport only
       -6          Use IPv6 transport only
       -r N        Maximum # SOA query retries for each server (default 5)
       -a ns1,..   Specify additional nameserver names/addresses to query


$ ./check_serial.py upenn.edu
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

```
