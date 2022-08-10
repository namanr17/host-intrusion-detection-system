import pyshark
import operator

def null_scan():
    cap= pyshark.LiveCapture(interface='wlp2s0', bpf_filter='tcp')
    cap.set_debug()
    ip_add={}
    count = 0
    under_attack = 0
    while True:
        for pkt in cap.sniff_continuously(packet_count=200):
            if(str(pkt.tcp.flags)=="0x00000000"):
                count+=1
                ip=pkt.ip.src
                if ip not in ip_add:
                    ip_add[ip]=1
                else:
                    ip_add[ip]+=1

        if count > 100:
            print("ok")
            if under_attack == 0:
                print('EXCESSIVE NULL SCAN DETECTED, SOURCE IP: ', max(ip_add.items(), key=operator.itemgetter(1))[0])
                return 
        elif count < 100:
            under_attack=0

null_scan()
