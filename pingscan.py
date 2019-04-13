#!/usr/bin/env python3

from scapy.all import *

def pingscan(ip):
    """
    pingscan(ip)

    Ping the incoming IP.
    ip: Pass in an IP like 192.168.1.0 or 192.168.1.0/24
    """
    ping = IP(dst=ip) / ICMP()
    result = sr(ping, timeout=10, verbose=False)
    
    alive = []
    for answer in result[0]:
        answerpkt = answer[1]
        if answerpkt[1].fields['type'] == answerpkt[1].fields['code'] == 0:
            alive.append(answerpkt[0].fields['src'])

    return alive


if __name__ == '__main__':
    ip = input("Enter the IP address:")
    result = pingscan(ip)
    for i in result:
        print("{} is alive.".format(i))
