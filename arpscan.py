#!/usr/bin/env python3

from scapy.all import *

def arpscan(ip):
    """
    pingscan(ip)

    ARP the incoming IP.
    ip: Pass in an IP like 192.168.1.0 or 192.168.1.0/24
    """
    answer, uanswer = srp( \
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), \
        inter=0.1, timeout=2, verbose=False \
    )
    
    mac_list = []
    for send, recv in answer:
        if recv[ARP].op == 2:
            mac_list.append((recv[ARP].psrc, recv[Ether].hwsrc))

    return mac_list


if __name__ == '__main__':
    ip = input("Enter IP address:")
    result = arpscan(ip)
    for i,j in result:
        print(i, "\t", j)

