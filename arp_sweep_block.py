import pyshark
import operator
import os

def arp_sweep():
    capture = pyshark.FileCapture('./arp_scan.pcap', display_filter = "arp")
    capture.set_debug()
    while True:
        mac_addresses={}
        arp_count=0
        under_attack = 0
        for packet in capture:
            dest_mac = packet.eth.dst
            packet_type =  str(packet.arp.opcode) 
            if packet_type == '1':
                arp_count+=1
                src_mac = packet.eth.src
                if src_mac not in mac_addresses:
                    mac_addresses[src_mac]=1;
                elif src_mac in mac_addresses:
                    mac_addresses[src_mac]+=1
        if arp_count > 100:
            if under_attack == 0:
                mac = max(mac_addresses.items(), key=operator.itemgetter(1))[0]
                print('------------------------------------------------------')
                print("EXCESSIVE ARP TRAFFIC DETECTED, SOURCE MAC: %s" %mac )
                return mac
        elif arp_count<100:
            under_attack=0

if __name__ ==  "__main__":
    block = arp_sweep()
    command = "iptables -A INPUT -j DROP -m mac --mac-source " + block
    
    if (os.system(command) == 0):
        print("%s BLOCKED SUCCESSFULLY" %block)
