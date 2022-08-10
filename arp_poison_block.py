import pyshark
import operator
import os

def arp_poisoning():
    capture = pyshark.FileCapture('./arp_poison.pcap', display_filter='arp')
    capture.set_debug()
    mac_ip={}
    while True:
        for packet in capture:
            packetType = str(packet.arp.opcode)
            if packetType == '2' or packetType == '1':
                mac = str(packet.arp.src_hw_mac)
                ip = str(packet.arp.src_proto_ipv4)
                if mac in mac_ip:
                    if mac_ip[mac] != ip:
                        print("\nARP POISONING ATTACK DETECTED FROM IP: " + ip)
                        return ip
                else:
                    mac_ip[mac] = ip

if __name__ ==  "__main__":
    block = arp_poisoning()
    command = "iptables -A INPUT -s " + block + " -j DROP"
    
    if (os.system(command) == 0):
        print("%s BLOCKED SUCCESSFULLY" %block)
