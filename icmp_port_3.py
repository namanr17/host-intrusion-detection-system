import pyshark

def udp_sweep():
	cap = pyshark.LiveCapture(interface='Wi-Fi',bpf_filter='icmp port 3 and code
	3',only_summaries='True')
	while True:
	icmp_ip_add={}
	for pkt in cap.sniff_continuously(timeout=10):
		if str(pkt.ip.src) not in str(icmp_ip_add)
			icmp_ip_add{pkt.ip.src}=1
		else
			icmp_ip_add{pkt.ip.src}+=1
	for pkts,count in icmp_ip_add.items()
		if count>1000
			print("UDP sweep attack ip: ",pkts)	


def ip_protocol_scan():
	cap = pyshark.LiveCapture(interface='Wi-Fi',bpf_filter='icmp port 3 and code 2",only_summaries='True')
	while True:
	ipps_ip_add={}
	for pkt in cap.sniff_continuously(timeout=10):
		if str(pkt.ip.src) not in str(ipps_ip_add)
			ipps_ip_add{pkt.ip.src}=1
		else
			ipps_ip_add{pkt.ip.src}+=1
	for pkts,count in ipps_ip_add.items()
		if count>1
			print("IP protocol scan attack ip: ",pkts)	

def null_scan():
	cap = pyshark.LiveCapture(interface='Wi-Fi',bpf_filter='tcp.falgs= 0x000',only_summaries='True')
	null_scan_ip_add={}
	while True:
	for pkt in cap.sniff_continuously(timeout=2):
		if str(pkt.ip.src) not in str(null_scan_ip_add)
			null_scan_ip_add{pkt.ip.src}=1
		else
			null_scan_ip_add{pkt.ip.src}+=1
	for pkts,count in null_scan_ip_add.items()
		if count>5
			print("Null scan attack ip: ",pkts)	
		

