addrwatch
=========

This is a tool similar to arpwatch. It main purpose is to monitor network and 
log discovered ethernet/ip pairings.

Main features of addrwatch:

* IPv4 and IPv6 address monitoring
* Monitoring multiple network interfaces with one daemon
* Monitoring of VLAN tagged (802.1Q) packets.
* Output to stdout, plain text file, syslog, sqlite3 db, MySQL db
* IP address usage history preserving output/logging

Addrwatch is extremely useful in networks with IPv6 autoconfiguration 
(RFC4862) enabled. It allows to track IPv6 addresses of hosts using IPv6 
privacy extensions (RFC4941).

The main difference between arpwatch and addrwatch is the format of output
files.

Arpwatch stores only current state of the network ethernet/ip pairings and 
allows to send email notification when a pairing change occurs. This is fine
for small and rather static networks. In arpwatch case all the history of
pairings is saved only in administrators mailbox. When arpwatch is used for
monitoring dozen or more networks it becomes hard to keep track of the historic
address usage information.

Addrwatch do not keep persistent network pairings state but instead logs all 
the events that allow ethernet/ip pairing discovery. For IPv4 it is ARP 
requests, ARP replies and ARP ACD (Address Conflict Detection) packets. For 
IPv6 it uses ICMPv6 Neighbor Discovery and (DAD) Duplicate Address Detection 
packets (Neighbor Solicitations, Neighbor Advertisements).

The output file produced by addrwatch is similar to arpwatch. Example of
addrwatch output file:

```
1329486484 eth0 0 00:aa:bb:cc:dd:ee fe80::2aa:bbff:fecc:ddee ND_NS
1329486485 eth0 0 00:aa:bb:cc:dd:ee 192.168.1.1 ARP_REQ
1329486485 eth0 0 00:aa:bb:ff:00:11 192.168.1.3 ARP_ACD
1329486486 eth0 7 00:11:11:11:11:11 fe80::211:11ff:fe11:1111 ND_NS
1329486487 eth0 7 00:22:22:22:22:22 fe80::222:22ff:fe22:2222 ND_DAD
1329486488 eth0 7 00:33:33:33:33:33 192.168.2.2 ARP_REQ
```

For each pairing discovery event addrwatch produce time-stamp, interface, 
vlan_tag (untagged packets are marked with 0 vlan_tag), ethernet address, IP 
address and packet type separated by spaces.

To prevent addrwatch from producing too many duplicate output data in active
networks rate-imiting should be used. Read more in 'Ratelimit' section. 

Modular architecture v1.0
-------------------------

Since version v1.0 addrwatch was rewritten to be more modular. Different output
modules can be configured and started independently from the main data
collection service.

Application architecture:

```
                                               +------------------+
                                           +-->| addrwatch_stdout |
                                           |   +------------------+
                                           |
                                           |   +------------------+
             +-------------+               +-->| addrwatch_syslog |
     network |             | shared memory |   +------------------+
    --------->  addrwatch  +-------------->|
             |             |               |   +------------------+
             +-------------+               +-->| addrwatch_mysql  |
                                               +------------------+
```

In the diagram boxes represent separate processes. Main **addrwach** process is
responsible for listening on all configured network interfaces and dumping all
data to a shared memory segment. Output modules have be be started separately,
they poll shared memory segment for changes and writes data to a specific output
format. Current version supports **stdout**, **syslog** and **mysql** output
formats.

**Note:** in addrwatch version v1.0 mysql output schema was changed to an more
efficient one, by storing IP and mac addresses as binary values. To migrate
existing addrwatch v0.8 installations to v1.0 there is a migration script
*migrate_0.8_to_1.0.sql* in the main repository directory.

Installation
------------

To compile addrwatch you must have following shared libraries:

* libpcap
* libevent
* mysqlclient (optional)

To compile addrwatch with mysql support:

```
$ ./configure --enable-mysql
$ make
$ make install
```

To compile basic addrwatch version:

```
$ ./configure
$ make
$ make install
```

If you do not want to install addrwatch to the system, skip the 'make install' 
step. You can find main addrwatch binary and all output addrwatch\_\* binaries
in 'src' directory.

Building from repo
------------------

If sources are obtained directly from the git repository (instead of
distribution source package) project has to be bootstrapped using
autoreconf/automake. A helper shell script `bootstrap.sh` is included in the
repository for that. Note that bootstraping autotools project requires autoconf
and automake to be available on the system.

Example command to bootstrap autotools:

```
./bootstrap.sh
```

To automatically check source style before commiting use provided pre-commit git
hook:

```
git config core.hooksPath .githooks
```

Usage
-----

To simply try out addrwatch start it without any arguments:

```
$ addrwatch
```

When started like this addrwatch opens first non loopback interface and start
logging event to the console without writing anything to disk. All events
are printed to stdout, debug, warning, and err messages are sent to syslog and
printed to stderr.

If you get error message:
addrwatch: ERR: No suitable interfaces found!

It usually means you started addrwatch as normal user and do not have sufficient
privileges to start sniffing on network interface. You should start addrwatch as
root:

```
$ sudo addrwatch
```

You can specify which network interface or interfaces should be monitored by
passing interface names as arguments. For example:

```
$ addrwatch eth0 tap0
```

To find out about more usage options:

```
$ addrwatch --help
```

In production environment it is recommended to start main addrwatch binary in a
daemon mode, and use separate output processes for logging data. Example:

```
$ ./addrwatch -d eth0
$ ./addrwatch_stdout
```

Ratelimiting
------------

If used without ratelimiting addrwatch reports etherment/ip pairing everytime it
gets usable ARP or IPv6 ND packet. In actively used networks it generates many
duplicate pairings especially for routers and servers.

Ratelimiting option '-r NUM' or '--ratelimit=NUM' surpress output of duplicate
pairings for at least NUM seconds. In other words if addrwatch have discovered 
some pairing (mac,ip) it will not report (mac,ip) again unless NUM seconds have
passed.

There is one exception to this rule to track ethernet address changes. If
addrwatch have discovered pairings: (mac1,ip),(mac2,ip),(mac1,ip) within
ratelimit time window it will report all three pairings. By doing so 
ratelimiting will not loose any information about pairing changes.

For example if we have a stream of events:

| time | MAC address       | IP address
|------|-------------------|------------
| 0001 | 11:22:33:44:55:66 | 192.168.0.1
| 0015 | 11:22:33:44:55:66 | 192.168.0.1
| 0020 | aa:bb:cc:dd:ee:ff | 192.168.0.1
| 0025 | aa:bb:cc:dd:ee:ff | 192.168.0.1
| 0030 | 11:22:33:44:55:66 | 192.168.0.1
| 0035 | 11:22:33:44:55:66 | 192.168.0.1
| 0040 | aa:bb:cc:dd:ee:ff | 192.168.0.1
| 0065 | aa:bb:cc:dd:ee:ff | 192.168.0.1

With --ratelimit=100 we would get:

| time | MAC address       | IP address
|------|-------------------|------------
| 0001 | 11:22:33:44:55:66 | 192.168.0.1
| 0020 | aa:bb:cc:dd:ee:ff | 192.168.0.1
| 0030 | 11:22:33:44:55:66 | 192.168.0.1
| 0040 | aa:bb:cc:dd:ee:ff | 192.168.0.1

Without such exception output would be:

| time | MAC address       | IP address
|------|-------------------|------------
| 0001 | 11:22:33:44:55:66 | 192.168.0.1
| 0020 | aa:bb:cc:dd:ee:ff | 192.168.0.1

And we would loose information that address 192.168.0.1 was used by ethernet
address 11:22:33:44:55:66 between 30-40th seconds.

To sum up ratelimiting reduces amount of duplicate information without loosing
any ethernet address change events.

Ratelimit option essentially limits data granularity for IP address usage 
duration information (when and for what time period specific IP address was 
used). On the other hand without ratelimiting at all you would not get very 
precise IP address usage duration information anyways because some hosts might 
use IP address without sending ARP or ND packets as often as others 
do.


If NUM is set to 0, ratelimiting is disabled and all pairing discovery events
are reported.

If NUM is set to -1, ratelimiting is enabled with infinitely long time window
therefore all duplicate pairings are suppressed indefinitely. In this mode 
addrwatch acts almost as arpwatch with the exception that ethernet address 
changes are still reported.

It might look tempting to always use addrwatch with --ratelimit=-1 however by
doing so you loose the information about when and for what period of time 
specific IP address was used. There will be no difference between temporary IPv6
addressed which was used once and statically configured permanent addresses.

Event types
-----------

Ethernet/ip pairing discovery can be triggered by these types of events:

* ARP_REQ - ARP Request packet. Sender hardware address (ARP header) and sender
  protocol address (ARP header) is saved.
* ARP_REP - ARP Reply packet. Sender hardware address (ARP header) and sender
  protocol address (ARP header) is saved.
* ARP_ACD - ARP Address collision detection packet. Sender hardware address
  (ARP header) and target protocol address (ARP header) is saved.
* ND_NS - Neighbor Solicitation packet. Source link-layer address (NS option)
  and source address (IPv6 header) is saved.
* ND_NA - Neighbor Advertisement packet. Target link-layer address (NA option)
  and source address (IPv6 header) is saved.
* ND_DAD - Duplicate Address Detection packet. Source MAC (Ethernet header)
  and target address (NS header) is saved.

