import pyshark
import operator

def ping_sweep():
    capture = pyshark.LiveCapture(interface='wlp2s0', display_filter="icmp")
    under_attack=0
    while True:
        ip_address={}
        count=0    
        for packet in capture.sniff_continuously(packet_count=200):
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
                 print('EXCESSIVE ICMP TRAFFIC DETECTED, SOURCE IP: ', max(ip_address.items(), key=operator.itemgetter(1))[0])
            under_attack=1
        elif count < 7:
            under_attack=0

ping_sweep()
