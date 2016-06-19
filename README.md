# tcpkiller

tcpkiller is a utility to kill all TCP connections on a network. It works by intercepting network traffic, and forging RST packets of existing connections to cause hangups. Works for both IPv4 connections and IPv6. 

tcpkiller is a sneaky way to kill network connections. Any targeted system will appear to work when examined through typical diagnostics - DNS will resolve, ICMP's will go through, and the network card will be able to connect to the network- but no TCP connections will be sustained. 

Currently, tcpkiller only supports Ethernet/wired systems, in which it's effectiveness is somewhat mitigated, as it may not see all of the packets on a network. Once testing has been completed on wireless systems and 802.11 is supported, it will kill every TCP connection going over an access point.

## Usage:

```
$ ./tcpkiller -i eth0
[*] Initialized tcpkiller on eth0 in quiet mode, targeting all. Press Ctrl-C to exit.
...
```

### Options:
 - ```-a, --allow``` do not attack this ip address's connections, whether it's the source or destination of a packet
 - ```-as,  --allow-source``` do not attack this ip address's connections, but only if it's the source of a packet
 - ```-ad, --allow-destination```do not attack this ip address's connections, but only if it's the destination of a packet
 - ```-t, --target``` actively target given ip address, whether it is the source or destination of a packet (and allow all other connections)
 - ```-ts, --target-source``` actively target this ip address, but only if it's the source
 - ```-td, --target-destination``` actively target this ip address, but only if it's the destination of a packet
 - ```-o, --allow-port``` do not attack any connections involving this port, whether it's the source or destination of a packet
 - ```-os, --allow-source-port``` do not attack any connections involving this port, but only if it's the source of a packet
 - ```-od, --allow-destination-port``` do not attack any connections involving this port, but only if it's the destination of a packet
 - ```-p, --target-port``` actively target any connections involving these ports whether it is the source or destination of a packet (and allow all other connections)
 - ```-ps, --target-source-port``` actively target any connections involving this port, but only if it's the source
 - ```-pd, --target-destination-port``` actively target any connections involving this port, but only if it's the destination of a packet
 - ```-n, --noisy``` sends many more packets to attempt connection resets to increase effectiveness [this is usually unnecessary]
 - ```-r, --randomize {often,half,seldom,all}``` target only SOME of the matching packets for increased stealthiness. defaults to "all"
 - ```-i, --interface``` specify interface to listen on 
 - ```-v, --verbose``` verbose output
 - ```-h, --help``` prints usage and help menu

## Installation

tcpkiller relies on [Scapy](http://www.secdev.org/projects/scapy/), and is designed to run on Ubuntu or Kali Linux. Due to restrictions on network card promiscuous mode in OS X and Windows, these platforms are not supported. 

To install Scapy: 
```bash
$ sudo apt-get install scapy
```

To setup tcpkiller:

```
$ git clone https://github.com/Kkevsterrr/tcpkiller && cd tcpkiller
$ sudo chmod +x tcpkiller
$ ./tcpkiller -i <interface>
...
```
