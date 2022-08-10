import pyshark
import operator

def arp_sweep():
    capture = pyshark.LiveCapture(interface='wlp2s0', display_filter = "arp")
    capture.set_debug()
    print('CAPTURING')
    while True:
        mac_addresses={}
        arp_count=0
        under_attack = 0
        for packet in capture.sniff_continuously(packet_count=200):
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
                print('EXCESSIVE ARP TRAFFIC DETECTED, SOURCE MAC: ', max(mac_addresses.items(), key=operator.itemgetter(1))[0])
                return 
        elif arp_count<100:
            under_attack=0

arp_sweep()
