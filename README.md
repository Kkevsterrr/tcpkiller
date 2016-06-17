# tcpkiller

tcpkiller is a utility to kill all TCP connections on a network. It works by intercepting network traffic, and forging RST packets of existing connections to cause hangups. Currently, it only works for IPv4 connections, but IPv6 support is on the way. 

Note that tcpkiller's effectiveness is mitigated somewhat on ethernet/wired systems, where the system does not receive all of the packets of the system. On a wifi network, however, it can kill every TCP connection going over an access point.

## Usage:

```
$ ./tcpkiller -i eth0
[*] Initialized tcpkiller
...
```

### Options:

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
