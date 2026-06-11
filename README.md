ZMap: The Internet Scanner
==========================

This repository is a fork of [ZMapv6](https://github.com/tumi8/zmap/) to support
[scanning for vulnerable tunnelling hosts](#tunnelling-protocol-modules) as used
in the paper "Haunted by Legacy: Discovering and Exploiting Vulnerable Tunnelling Host".

ZMap is a fast single packet network scanner designed for Internet-wide network
surveys. On a typical desktop computer with a gigabit Ethernet connection, ZMap
is capable scanning the entire public IPv4 address space in under 45 minutes. With
a 10gigE connection and [PF_RING](http://www.ntop.org/products/packet-capture/pf_ring/),
ZMap can scan the IPv4 address space in under 5 minutes.

ZMap operates on GNU/Linux, Mac OS, and BSD. ZMap currently has fully implemented
probe modules for TCP SYN scans, ICMP, DNS queries, UPnP, BACNET, and can send a
large number of [UDP probes](https://github.com/zmap/zmap/blob/master/examples/udp-probes/README).
If you are looking to do more involved scans, e.g.,
banner grab or TLS handshake, take a look at [ZGrab 2](https://github.com/zmap/zgrab2),
ZMap's sister project that performs stateful application-layer handshakes.

Installation
------------

**Instructions on building ZMap from source** can be found in [INSTALL](INSTALL.md).

Usage
-----

A guide to using ZMap is found in our [GitHub Wiki](https://github.com/zmap/zmap/wiki).

Additional Arguments
-----------------------

Most tunneling probe modules accept one or more of the following additional arguments (see examples below). Their meanings are as follows:
* `--external-ipv4-address $IPV4_ADDR`: Refers to the global IPv4 address of the scanning host. This argument ensures responses are routed back to the scanner.
* `--external-ipv6-address $IPV6_ADDR`: Refers to the global IPv6 address of the scanning host. This argument ensures responses are routed back to the scanner.
* `--spoofing-address-v4 $RANDOM_IPV4`: A chosen spoofed address. This argument allows for the identification of unfiltered networks, i.e., vulnerable hosts will send a response with the given spoofed IPv4 address as the source address.
* `--spoofing-address-v6 $RANDOM_IPV6`: A chosen spoofed address. This argument allows for the identification of unfiltered networks, i.e., vulnerable hosts will send a response with the given spoofed IPv6 address as the source address.

Note that some modules, such as spoofing, subnet, etc, also use a `-f` parameter. This parameter is used to ensure the correct address of the vulnerable host is written to the output file (instead of the possibly spoofed source address of the reply).

Tunnelling Protocol Modules
-----------------------

We added support for the identification of vulnerable tunnelling protocols. The modules are the following:

IPIP
-----------------------

* IPIP Standard Scan: `ipip`,`ipip_subnet`, and `ipip_spoofing` (Section 3.2.1)
```bash
# Standard scan (inner packet has the target as source and the external-ipv4-address as destination)
zmap -M ipip --output-module="csv" -o output.csv --external-ipv4-address $IPV4_ADDR 
# Subnet spoofing scan (inner packet has a source IP address within the subnet of the host being scanned)
zmap -M ipip_subnet --output-module="csv" -o output.csv --external-ipv4-address $IPV4_ADDR -f actual_src
# Spoofing scan (inner packet has the given spoofing-address-v4 as the source IP address)
zmap -M ipip_spoofing --output-module="csv" -o output.csv --external-ipv4-address $IPV4_ADDR --spoofing-address-v4 $SPOOFED_ADDR -f actual_src
```
* IPIP ICMP Echo/Reply scan: `ipip_echo` (Section 3.2.2)
```bash
# ICMP Echo/Reply scan (ping reply has a source IP address equal to the host being scanned)
zmap -M ipip_echo --output-module="csv" -o output.csv --external-ipv4-address $IPV4_ADDR
```
* IPIP TTL Expired scan: `ipip_ttl` (Section 3.2.3)
```bash
# TTL Expired Scan (inner packet has the external-ipv4-address as source and a random spoofing-address-v4 as destination, with the TTL of the inner packet set to 1)
zmap -M ipip_ttl --output-module="csv" -o output.csv --external-ipv4-address $IPV4_ADDR --spoofing-address-v4 $RANDOM_IPV4
```
GRE
-----------------------

* GRE Standard Scan: `gre`,`gre_subnet` and `gre_spoofing` (Section 3.2.1)
```bash
zmap -M gre --output-module="csv" -o output.csv --external-ipv4-address $IPV4_ADDR 
# Subnet spoofing scan (inner packet has a source IP address within the subnet of the host being scanned)
zmap -M gre_subnet --output-module="csv" -o output.csv --external-ipv4-address $IPV4_ADDR -f actual_src
# Spoofing scan (inner packet has the given spoofing-address-v4 as the source IP address)
zmap -M gre_spoofing --output-module="csv" -o output.csv --external-ipv4-address $IPV4_ADDR --spoofing-address-v4 $SPOOFED_ADDR -f actual_src

```
* GRE ICMP Echo/Reply Scan: `gre_echo` (Section 3.2.2)
```bash
# ICMP Echo/Reply scan (ping reply has a source IP address equal to the host being scanned)
zmap -M gre_echo --output-module="csv" -o output.csv --external-ipv4-address $IPV4_ADDR
```
* GRE TTL Expired scan: `gre_ttl` (Section 3.2.3)
```bash
# TTL Expired Scan (inner packet has the external-ipv4-address as source and a random spoofing-address-v4 as destination, with the TTL of the inner packet set to 1)
zmap -M gre_ttl --output-module="csv" -o output.csv --external-ipv4-address $IPV4_ADDR --spoofing-address-v4 $RANDOM_IPV4
```

6in4
-----------------------

* 6in4 Standard Scan: `6in4` (Section 3.2.1)
```bash
# Standard scan (inner IPv6 packet has the spoofing-address-v6 as source and the external-ipv6-address as destination)
zmap -M 6in4 --external-ipv6-address $IPV6_ADDR --spoofing-address-v6 $SPOOFED_ADDR_V6 -o output.csv -f actual_src
```
* 6in4 6to4 & Mapped Scans: `6in4_6to4` and `6in4_mapped` (Section 3.2.2). Note that the ouput will contain the vulnerable IPv4 host's mapped address, i.e., either `2002:VULN_IPv4_ADDR` or `::ffff:VULN_IPv4_ADDR`.
```bash
# 6to4 scan (inner IPv6 packet has the target's 6to4 address as source and the external-ipv6-address as destination)
zmap -M 6in4_6to4 --external-ipv6-address $IPV6_ADDR -o output.csv -f saddr
# Mapped scan (inner IPv6 packet has the target's mapped address as source and the external-ipv6-address as destination)
zmap -M 6in4_mapped --external-ipv6-address $IPV6_ADDR -o output.csv -f saddr

```
* 6in4 TTL Expired scan: `6in4_ttl` (Section 3.2.3)
```bash
# TTL Expired Scan (inner IPv6 packet has the external-ipv6-address as source and the target's 6to address as destination, with the TTL of the inner packet set to 1)
zmap -M 6in4_ttl --external-ipv6-address $IPV6_ADDR -o output.csv -f actual_src,saddr
```
GRE6
-----------------------

* GRE6 Standard scan: `gre6`,`gre6_subnet` and `gre6_spoofing` (Section 3.2.1)
```bash
# Standard scan (inner IPv6 packet has the ipv6-target-file as source and the ipv6-source-ip as destination)
zmap -M gre6 --ipv6-source-ip $IPV6_ADDR --ipv6-target-file ipv6_addresses.txt -o output.csv
# Subnet spoofing scan (inner IPv6 packet has a source IP address within the subnet of the host being scanned)
zmap -M gre6_subnet --ipv6-source-ip $IPV6_ADDR --ipv6-target-file ipv6_addresses.txt -o output.csv -f saddr 
# Spoofing scan (inner IPv6 packet has the given spoofing-address-v6 as the source IP address)
zmap -M gre6_spoofing --ipv6-source-ip $IPV6_ADDR --ipv6-target-file ipv6_addresses.txt --spoofing-address-v6 $SPOOFED_ADDR_V6 -o output.csv -f saddr
```
* GRE6 ICMPv6 Echo/Reply scan: `gre6_icmp` (Section 3.2.2)
```bash
# ICMPv6 Echo/Reply scan (ping reply has a source IP address equal to the host being scanned)
zmap -M gre6_icmp --ipv6-source-ip $IPV6_ADDR --ipv6-target-file ipv6_addresses.txt -o output.csv
```
* GRE6 HLIM Expired scan: `gre6_hlim` (Section 3.2.3)
```bash
# HLIM Expired Scan (inner IPv6 packet has the ipv6-source-ip as source and a random spoofing-address-v6 address as destination, with the hlim of the inner packet set to 0)
zmap -M gre6_hlim --ipv6-source-ip $IPV6_ADDR --ipv6-target-file ipv6_addresses.txt --spoofing-address-v6 $RANDOM_ADDR_V6 -o output.csv
```

IP6IP6
-----------------------

* IP6IP6 Standard scan: `ip6ip6`,`ip6ip6_subnet` and `ip6ip6_spoofing` (Section 3.2.1)
```bash
zmap -M ip6ip6 --ipv6-source-ip $IPV6_ADDR --ipv6-target-file ipv6_addresses.txt -o output.csv
# Subnet spoofing scan (inner IPv6 packet has a source IP address within the subnet of the host being scanned)
zmap -M ip6ip6_subnet --ipv6-source-ip $IPV6_ADDR --ipv6-target-file ipv6_addresses.txt -o output.csv -f saddr
# Spoofing scan (inner IPv6 packet has the given spoofing-address-v6 as the source IP address)
zmap -M ip6ip6_spoofing --ipv6-source-ip $IPV6_ADDR --spoofing-address-v6 $SPOOFED_ADDR_V6 --ipv6-target-file ipv6_addresses.txt -o output.csv -f saddr
```
* IP6IP6 ICMPv6 Echo/Reply scan: `ip6ip6_echo` (Section 3.2.2)
```bash
# ICMPv6 Echo/Reply scan (ping reply has a source IP address equal to the host being scanned)
zmap -M ip6ip6_echo --ipv6-source-ip $IPV6_ADDR --ipv6-target-file ipv6_addresses.txt --spoofing-address-v6 $RANDOM_ADDR_V6 -o output.csv
```
* IP6IP6 HLIM Expired scan: `ip6ip6_hlim` (Section 3.2.3)
```bash
# HLIM Expired Scan (inner IPv6 packet has the ipv6-source-ip as source and a random spoofing-address-v6 address as destination, with the hlim of the inner packet set to 0)
zmap -M ip6ip6_hlim --ipv6-source-ip $IPV6_ADDR --ipv6-target-file ipv6_addresses.txt --spoofing-address-v6 $RANDOM_ADDR_V6 -o output.csv
```

4in6
-----------------------

* 4in6 Spoofing: `4in6_spoofing`
```bash
# Spoofing scan (the inner source address is the spoofing-address-v4 and the destination is the external-ipv4-address )
zmap -M 4in6_spoofing --ipv6-source-ip $IPV6_ADDR --ipv6-target-file ipv6_addr.txt --spoofing-address-v4 $SPOOFED_ADDR --external-ipv4-address $IPV4_ADDR -o output.csv -f actual_src
```
* 4in6 TTL Expired: `4in6_ttl`
```bash
# TTL Expired scan (the inner source address is the external-ipv4-address and the destination is the spoofing-address-v4, with the TTL of the inner packet set to 1 )
# actual_src_index is the index line of the ipv6_addr.txt corresponding to the host
zmap -M 4in6_ttl --ipv6-source-ip $IPV6_ADDR --ipv6-target-file ipv6_addr.txt --spoofing-address-v4 $RANDOM_ADDR --external-ipv4-address $IPV4_ADDR -o output.csv -f actual_src_index,tunnel_addr
```

GUE
-----------------------

* GUE Standard Scan: `gue` (Section 3.2.1). Note that in our scans we never detected a vulnerable GUE host.
```bash
# Standard scan (inner packet has the target as source and the external-ipv4-address as destination)
zmap -M gue -p 6080 --output-module="csv" -o output.csv --external-ipv4-address $IPV4_ADDR
```

Lost in Encapsulation: Exploiting Open Tunnelling Hosts and Attacking Private Networks
-----------------------

GRETAPv6 Multicast Scan
-----------------------
```bash
zmap -M gretap6_multicast --output-module="csv" -o gretap6.csv --external-ipv6-address $IPV6_ADDR --spoofing-address-v6 ff02::1 -f saddr,actual_src
```

GRETAP
-----------------------
```bash
zmap -M gre_broadcast --output-module="csv" -o gretap_broadcast.csv --external-ipv4-address $IPV4_ADDR -f saddr,actual_src
```

IPIP NAT
-----------------------
```bash
zmap -M ipip_nat --output-module="csv" -o ipip_nat.csv --spoofing-address-v4 $PRIVATE_IP --external-ipv4-address $IPV4_ADDR -f saddr,actual_src
```

GRE NAT
-----------------------
```bash
zmap -M gre_nat --output-module="csv" -o gre_nat.csv --spoofing-address-v4 $PRIVATE_IP --external-ipv4-address $IPV4_ADDR -f saddr,actual_src
```

IPIP Two-Way Proxy Scan
-----------------------
Make sure to execute the following on the first scanner (the server running the ZMap scan): ```sudo iptables -A OUTPUT -d $SCANNER2_IP -p icmp --icmp-type echo-reply -j DROP``
```bash
# Results are collected at SERVER2
zmap -M ipip_doubleproxy --output-module="csv" -o ipip_doubleproxy.csv --spoofing-address-v4 $SERVER_2 --external-ipv4-address $IPV4_ADDR
```
```bash
# At Server 2
sudo python3 double_proxy_listener.py
```

GRE Two-Way Proxy Scan
-----------------------
Make sure to run the following on the first scanner (the server running the ZMap scan): ```sudo iptables -A OUTPUT -d $SCANNER2_IP -p icmp --icmp-type echo-reply -j DROP```
```bash
# Results are collected at SERVER2
zmap -M gre_doubleproxy --output-module="csv" -o gre_doubleproxy.csv --spoofing-address-v4 $SERVER_2 --external-ipv4-address $IPV4_ADDR
```
```bash
# At Server 2
sudo python3 double_proxy_listener.py
```

License and Copyright
---------------------

ZMap Copyright 2017 Regents of the University of Michigan

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See LICENSE for the specific
language governing permissions and limitations under the License.

