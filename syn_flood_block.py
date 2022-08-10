import pyshark
import operator
import os

def syn_flooding():
    capture = pyshark.FileCapture('./syn_flood.pcap', display_filter = 'tcp')
    capture.set_debug()
    under_attack = 0
    while True:
        ip_addresses = {}
        syn_count = 0
        for packet in capture:
            if (str(packet.tcp.flags) == "0x00000002"):
                src_ip = str(packet.ip.src)
                syn_count += 1
                if src_ip not in ip_addresses:
                    ip_addresses[src_ip] = 1
                elif src_ip in ip_addresses:
                    ip_addresses[src_ip] += 1
                if (syn_count > 20):
                    ip = max(ip_addresses.items(), key=operator.itemgetter(1))[0]  
                    print("SYN FLOODING ATTACK DETECTED, SOURCE IP: %s" %ip)
                    return ip

if __name__ ==  "__main__":
    block = syn_flooding()
    command = "iptables -A INPUT -s " + block + " -j DROP"
     
    if (os.system(command) == 0):
        print("%s BLOCKED SUCCESSFULLY" %block)
