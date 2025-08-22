 Scapy Network Scanner

A simple Python-based network scanner built using Scapy.
It supports:

 Checking if a host/IP is alive (ICMP ping)

 Scanning single ports or port ranges (TCP SYN scan)

 DNS lookup test against an IP (UDP/53)

 IP range scanning with threading for faster results

 Features

Port scanning

Single ports: -p 80 443

Port ranges: -p 20-100

Alive check

Single IP: -a 192.168.1.1

Range: -a 192.168.1.1-192.168.1.20

DNS check

-d 8.8.8.8
