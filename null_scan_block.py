import pyshark
import operator
import os

def null_scan():
    cap=pyshark.FileCapture('./nmap_null.pcap', display_filter='tcp')
    cap.set_debug()
    null_scan_ip_add={}
    count=0
    while True:
        for pkt in cap:
            if (str(pkt.tcp.flags)=="0x00000000"):
                count+=1
                if str(pkt.ip.src) not in null_scan_ip_add:
                    null_scan_ip_add[pkt.ip.src]=1
                else:
                    null_scan_ip_add[pkt.ip.src]+=1
        if count>100:
            ip = max(null_scan_ip_add.items(), key=operator.itemgetter(1))[0]
            print("----------------------------------------------------------")
            print("NULL SCAN DETECTED, SOURCE IP: %s" %ip)
            return ip

if __name__ ==  "__main__":
    block = null_scan()
    command = "iptables -A INPUT -s " + block + " -j DROP"
    
    if (os.system(command) == 0):
        print("%s BLOCKED SUCCESSFULLY" %block)
