#!/usr/bin/env python3

from scapy.all import *

def pingscan(ip):
    ping = IP(dst=ip) / ICMP()
    result = sr(ping, timeout=10, verbose=False)
    
    alive = []
    for answer in result[0]:
        answerpkt = answer[1]
        if answerpkt[1].fields['type'] == 0 \
                and answerpkt[1].fields['code'] == 0:
            alive.append(answerpkt[0].fields['src'])
    return alive

if __name__ == '__main__':
    ip = input("输入IP地址:")
    result = pingscan(ip)
    for i in result:
        print("{} is alive.".format(i))

