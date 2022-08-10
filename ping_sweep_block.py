import pyshark
import operator
import os

def ping_sweep():
    capture = pyshark.FileCapture('./ping.pcap', display_filter="icmp")
    capture.set_debug()
    under_attack=0
    while True:
        ip_address={}
        count=0    
        for packet in capture:
            typ=str(packet.icmp.type)
            if typ=='0':
                count+=1
                ip=str(packet.ip.src)
                if ip in ip_address:
                    ip_address[ip]+=1
                else:
                    ip_address[ip]=1
            elif typ=='8':
                count+=1
                ip=str(packet.ip.dst)
                if ip in ip_address:
                    ip_address[ip]+=1
                else:
                    ip_address[ip]=1
        if count > 7:   
            if under_attack == 0:
                IP = max(ip_address.items(), key=operator.itemgetter(1))[0]
                print('--------------------------------------------------------------')
                print("EXCESSIVE ICMP TRAFFIC DETECTED, SOURCE IP: %s" %IP)
                return IP
            under_attack=1
        elif count < 7:
            under_attack=0

if __name__ ==  "__main__":
    block = ping_sweep()
    command = "iptables -A INPUT -s " + block + " -j DROP"
    
    if (os.system(command) == 0):
        print("%s BLOCKED SUCCESSFULLY" %block)
