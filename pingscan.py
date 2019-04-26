#!/usr/bin/env python3

from scapy.all import *

def pingscan(ip):
    """
    pingscan(ip)

    Ping the incoming IP.
    ip: Pass in an IP like 192.168.1.0 or 192.168.1.0/24
    """
    answer, uanswer = sr( \
        IP(dst=ip) / ICMP(), \
        timeout=10, verbose=False \
    )
    
    alive = []
    for send, recv in answer:
        if recv[ICMP].type == recv[ICMP].code == 0:
            alive.append(recv[0].src)

    return alive


if __name__ == '__main__':
    ip = input("Enter IP address:")
    result = pingscan(ip)
    for i in result:
        print("{} is alive.".format(i))
