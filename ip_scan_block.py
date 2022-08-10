import pyshark
import operator
import os

def ip_scan():
    capture = pyshark.FileCapture('./packet_ip_ub.pcap', display_filter = "icmp")
    capture.set_debug()
    while True:
        ip_add = {}
        for packet in capture:
            if(str(packet.icmp.type) == '3'):
                if str(packet.ip.src) not in str(ip_add):
                    ip_add[packet.ip.src] = 1
                else:
                    ip_add[packet.ip.src] += 1

        for ip, count in ip_add.items():
            if count > 1:
                print("IP PROTOCOL SCAN DETECTED, IP: ", ip)
                return ip

if __name__ ==  "__main__":
    block = ip_scan()
    command = "iptables -A INPUT -s " + block + " -j DROP"
    
    if (os.system(command) == 0):
        print("%s BLOCKED SUCCESSFULLY" %block)
