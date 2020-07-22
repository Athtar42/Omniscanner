# Ominiscanner - Network Forensics Tool
# ==================================================
# Need WinPcap(or Npcap) and TShark installed
# For windows please install Tshark(Wireshark) using choco
# choco install wireshark
# ==================================================
# Packages needed: GeoIP2 pyshark scapy
#
# Install:
# $ pip install geoip2
# $ pip install scapy
# $ pip install pyshark
# ==================================================


import os
import os.path
import argparse
import geoip2.database
import time
import pyshark
import csv
import sqlite3

import psutil
from psutil._common import bytes2human

from socket import *

from scapy import *
from scapy.all import *
from scapy.utils import RawPcapReader
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import ICMP, IP, TCP, UDP

pending_packets = []
total_packets = 0
number_packet = 300

# https://github.com/giampaolo/psutil/blob/master/scripts/ifconfig.py
def display_info():
	af_map = {
		socket.AF_INET: 'IPv4',
		socket.AF_INET6: 'IPv6',
		psutil.AF_LINK: 'MAC',
	}

	duplex_map = {
		psutil.NIC_DUPLEX_FULL: "full",
		psutil.NIC_DUPLEX_HALF: "half",
		psutil.NIC_DUPLEX_UNKNOWN: "?",
	}
	
	stats = psutil.net_if_stats()
	io_counters = psutil.net_io_counters(pernic=True)
	for nic, addrs in psutil.net_if_addrs().items():
		print("%s:" % (nic))
		if nic in stats:
			st = stats[nic]
			print("    stats          : ", end='')
			print("speed=%sMB, duplex=%s, mtu=%s, up=%s" % (
				st.speed, duplex_map[st.duplex], st.mtu,
				"yes" if st.isup else "no"))
		if nic in io_counters:
			io = io_counters[nic]
			print("    incoming       : ", end='')
			print("bytes=%s, pkts=%s, errs=%s, drops=%s" % (
				bytes2human(io.bytes_recv), io.packets_recv, io.errin,
				io.dropin))
			print("    outgoing       : ", end='')
			print("bytes=%s, pkts=%s, errs=%s, drops=%s" % (
				bytes2human(io.bytes_sent), io.packets_sent, io.errout,
				io.dropout))
		for addr in addrs:
			print("    %-4s" % af_map.get(addr.family, addr.family), end="")
			print(" address   : %s" % addr.address)
			if addr.broadcast:
				print("         broadcast : %s" % addr.broadcast)
			if addr.netmask:
				print("         netmask   : %s" % addr.netmask)
			if addr.ptp:
				print("      p2p       : %s" % addr.ptp)
		print("")


def geo_city(ip):
	try:
		reader = geoip2.database.Reader('GeoLite2-City.mmdb')
		response = reader.city(ip)
		country_name = response.country.name
		country_isocode = response.country.iso_code
		state_name = response.subdivisions.most_specific.name
		state_isocode = response.subdivisions.most_specific.iso_code
		city_name = response.city.name
		latitude = response.location.latitude
		longitude = response.location.longitude
		print("\n=====================================")
		print("[1] Country Name: ", country_name)
		print("[2] State Name: ", state_name)
		print("[3] State ISO Code: ", state_isocode)
		print("[4] City Name: ", city_name)
		print("[5] Coordinate: (", latitude, ",", longitude, ")")
		reader.close()
	except:
		print("\nCan't find anything. Please try again.")
		sys.exit(1)	

def arp_ping(host):
	print('Starting Scan Ping ARP for %s' %(host))
	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=host), timeout=2)
	ans.summary(lambda s_r: s_r[1].sprintf(Ether.src, ARP.psrc))

def icmp_ping(host):
	print('Starting Scan Ping ICMP for %s' %(host))
	ans, unans =srp(IP(dst=host)/ICMP())
	ans.summary(lambda s_r: s_r[1].sprint(IP.src, " is alive"))

def tcp_ping(host,port):
	ans, unans = sr(IP(dst=host)/TCP(port,flags="S"))
	ans.summary(lambda s_r: s_r[1].sprintf(IP.src, " is alive"))

def udp_ping(host,port=0):
	print('Starting Scan Ping UDP for %s' %(host))
	ans, unans = sr(IP(dst=host)/UDP(dport=port))
	ans.summary(lambda s_r: s_r[1].sprintf(IP.src, " is alive"))

def portscan(host):
	target = host
	common_ports = [20, 21, 22, 23, 25, 50, 51, 53, 67, 68, 69, 80, 109, 110, 123, 135, 136, 137, 138, 139, 143, 156, 161, 162, 389, 443, 546, 547, 993, 995, 2082, 2083, 2086, 2087, 3306, 8336, 1000]
	scan_option = input("\n[1] Input 1 to scan common ports. \n[2] Input 2 to scan a sequence of ports. \n[3] Input 3 for a single port scan. \n>>Please input your option: ")
	
	if scan_option == "1":
		try:
			start_time = time.time()
			print("\nStart scan on host: ", target)
			for port in common_ports:
				s = socket.socket(AF_INET, SOCK_STREAM)
				conn = s.connect_ex((target, port))
				if(conn == 0) :
					print('Port %d: OPEN' % (port,))
				s.close()				
			time_taken = time.time() - start_time
		except KeyboardInterrupt:
			print("\n[Warning] Scan stopped.")
			sys.exit(1)	

		print("\nTime taken: ", time_taken)

	elif scan_option == "2":
		try:
			start_port = int(input(">>Input start port: "))
			end_port = int(input(">>Input end port: "))
		except:
			print("\nPlease input numbers only.")
			sys.exit(1)	
		if  start_port >= end_port: #start_port.isdigit() == False or start_port.isdigit() == False
			print("\nThe the number of start port should be smaller than the end port. Please input again.")
			sys.exit(1)	
		else:
			try:
				start_time = time.time()
				print("\nStart scan on host: ", target)
				for port in range(start_port, end_port):
					s = socket.socket(AF_INET, SOCK_STREAM)
					conn = s.connect_ex((target, port))
					if(conn == 0) :
						print('Port %d: OPEN' % (port,))
					s.close()	
				time_taken = time.time() - start_time					
			except KeyboardInterrupt:
				print("\n[Warning] Scan stopped.")
				sys.exit(1)		

			print("\nTime taken: ", time_taken)

	elif scan_option == "3":
		try:
			port = int(input(">>Input the port you want to scan: "))
		except:
			print("\nPlease input numbers only.")
			sys.exit(1)	
		try:
			start_time = time.time()
			print("\nStart scan on host: ", target)
			s = socket.socket(AF_INET, SOCK_STREAM)
			conn = s.connect_ex((target, port))
			if(conn == 0) :
				print('Port %d: OPEN' % (port,))
			else:
				print("The port is closed, or unable to be scanned.")
			s.close()	
			time_taken = time.time() - start_time					
		except KeyboardInterrupt:
			print("\n[Warning] Scan stopped.")
			sys.exit(1)		
		print("\nTime taken: ", time_taken)
	else:
		print("\nSomething wrong happened. Please input again.")
		sys.exit(1)	


def handle_packet(packet):

	global pending_packets
	global total_packets
	global number_packet
	base_filename = "capture-"
	pending_packets.append(packet)
	total_packets += 1

	if len(pending_packets) >= number_packet:
		local_time = time.strftime("%Y-%m-%d-%H%M%S", time.localtime()) 
		filename = base_filename + str(total_packets) + "-" + local_time + ".pcap"
		print("File ", filename, " saved.")
		wrpcap(filename, pending_packets)
		pending_packets = []


def transfer_csv(filename):

	pcap_filename = filename
	name, extension = os.path.splitext(pcap_filename)
	if extension != ".pcap":
		print("Please input correct file name (.pcap file).")
		sys.exit(-1)
	if not os.path.exists(pcap_filename):
		print('Input pcap file "{}" does not exist'.format(pcap_filename), file=sys.stderr)
		sys.exit(-1)

	csv_filename = name+".csv"

	if os.path.exists(csv_filename):
		print('Output csv file "{}" already exists, ''won\'t overwrite'.format(csv_filename),file=sys.stderr)
		sys.exit(-1)

	pcap2csv(pcap_filename, csv_filename)

	
# https://github.com/vnetman/pcap2csv

def render_csv_row(packet_sh, packet_sc, fh_csv):

	ether_packet_sc = Ether(packet_sc)
	if ether_packet_sc.type != 0x800:
		print('Ignoring non-IP packet')
		return False
	
	# Assuming Ethernet + IPv4 here
	ip_packet_sc = ether_packet_sc[IP]       
	proto = ip_packet_sc.fields['proto']
	if proto == 17:
		udp_packet_sc = ip_packet_sc[UDP]
		l4_payload_bytes = bytes(udp_packet_sc.payload)
		l4_proto_name = 'UDP'
		l4_sport = udp_packet_sc.sport
		l4_dport = udp_packet_sc.dport
	elif proto == 6:
		tcp_packet_sc = ip_packet_sc[TCP]
		l4_payload_bytes = bytes(tcp_packet_sc.payload)
		l4_proto_name = 'TCP'
		l4_sport = tcp_packet_sc.sport
		l4_dport = tcp_packet_sc.dport
	else:
		# Not handling packets that are not UDP or TCP
		print('Ignoring non-UDP/TCP packet')
		return False

	# Each line of the CSV has this format
	fmt = '{0},{1},{2}({3}),{4},{5}:{6},{7}:{8},{9},{10}'
	#       |   |   |   |    |   |   |   |   |   |   |
	#       |   |   |   |    |   |   |   |   |   |   o-> {10} L4 payload hexdump
	#       |   |   |   |    |   |   |   |   |   o-----> {9}  total pkt length
	#       |   |   |   |    |   |   |   |   o---------> {8}  dst port
	#       |   |   |   |    |   |   |   o-------------> {7}  dst ip address
	#       |   |   |   |    |   |   o-----------------> {6}  src port
	#       |   |   |   |    |   o---------------------> {5}  src ip address
	#       |   |   |   |    o-------------------------> {4}  text description
	#       |   |   |   o------------------------------> {3}  L4 protocol
	#       |   |   o----------------------------------> {2}  highest protocol
	#       |   o--------------------------------------> {1}  time
	#       o------------------------------------------> {0}  frame number

	# Example:
	# 1,0.0,DNS(UDP),Standard query 0xf3de A www.cisco.com,192.168.1.116:57922,1.1.1.1:53,73,f3de010000010000000000000377777705636973636f03636f6d0000010001

	print(fmt.format(packet_sh.no,               # {0}
					 packet_sh.time,             # {1}
					 packet_sh.protocol,         # {2}
					 l4_proto_name,              # {3}
					 packet_sh.info,             # {4}
					 packet_sh.source,           # {5}
					 l4_sport,                   # {6}
					 packet_sh.destination,      # {7}
					 l4_dport,                   # {8}
					 packet_sh.length,           # {9}
					 l4_payload_bytes.hex()),    # {10}
		  file=fh_csv)

	return True

def pcap2csv(in_pcap, out_csv):

	# Open the pcap file with PyShark in "summary-only" mode
	pcap_pyshark = pyshark.FileCapture(in_pcap, only_summaries=True)
	pcap_pyshark.load_packets()
	pcap_pyshark.reset()

	frame_num = 0
	ignored_packets = 0

	print("Starting to transfer format from pcap to csv...")
	with open(out_csv, 'w') as fh_csv:
		# Open the pcap file with scapy's RawPcapReader, and iterate over each packet.
		print("Packet_No,Time,Protocol,Packet_Info,Source,Destination,Length,L4_Payload", file=fh_csv)
		for (packet_scapy, _) in RawPcapReader(in_pcap):
			try:
				packet_pyshark = pcap_pyshark.next_packet()
				frame_num += 1
				if not render_csv_row(packet_pyshark, packet_scapy, fh_csv):
					ignored_packets += 1
			except StopIteration:
				break

	print('{} packets read, {} packets ignored.'.
		  format(frame_num, ignored_packets))
	print("File ", out_csv," saved")

def transfer_sql(filename):
	csv_filename = filename
	name, extension = os.path.splitext(csv_filename)
	if extension != ".csv":
		print("Please input correct file name (.csv file).")
		sys.exit(-1)
	if not os.path.exists(csv_filename):
		print('Input csv file "{}" does not exist.'.format(csv_filename), file=sys.stderr)
		sys.exit(-1)
	database_name = name + ".db"
	if os.path.exists(database_name):
		print('The output file "{}" already exists. Please delete it first'.format(database_name), file=sys.stderr)
		sys.exit(-1)
	try:
		con = sqlite3.connect(database_name)
		cur = con.cursor()
		cur.execute("CREATE TABLE s (Packet_No,Time,Protocol,Packet_Info,Source,Destination,Length,L4_Payload);")
		print("Creating database...")
		with open(csv_filename,'rt') as fin: 
			dr = csv.DictReader(fin) 
			to_db = [(i['Packet_No'], i['Time'], i['Protocol'], i['Packet_Info'], i['Source'], i['Destination'], i['Length'], i['L4_Payload']) for i in dr]

		cur.executemany("INSERT INTO s (Packet_No,Time,Protocol,Packet_Info,Source,Destination,Length,L4_Payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?);", to_db)
		con.commit()
		con.close()
	except:
		print("Not supported, only support csv files generated by this program. Please try another file.")
		sys.exit(-1)
	print("File ",database_name, " saved.")

	

def parse_args():
	parser = argparse.ArgumentParser(description='')
	parser.add_argument("-i", "--info", dest="info", action="store_true", help="Display this PC's network information")
	parser.add_argument("-g", "--ip_geo", dest="ip_geo", type=str, help="Show the Geo Information of a IP address")
	parser.add_argument("-s", "--scan", dest="scan", type=str, help="Scan port")
	parser.add_argument("-p", "--ping", dest="ping", type=str)
	parser.add_argument("--port", dest="port", type=str)
	parser.add_argument("-m", "--method", dest="method", type=str)
	parser.add_argument("-c", "--capture", action="store_true", help="Save every 300 packets to a Pcap file.")
	parser.add_argument("--pcap2csv", dest="pcap2csv", type=str, help="Transfer a Pcap file to a CSV file")
	parser.add_argument("--csv2sql", dest="csv2sql", type=str, help="Transfer a CSV file to a SQLite file")
	parser.add_argument("--packet", dest="packet", type=int)
	return parser.parse_args()

def main():
	global number_packet

	args = parse_args()
	info = args.info
	ip_geo = args.ip_geo
	scan = args.scan
	ping = args.ping
	port = args.port
	method = args.method
	capture = args.capture
	pcap2csv = args.pcap2csv
	csv2sql = args.csv2sql
	packet = args.packet

	if ip_geo is not None or scan is not None or info is not None or ping is not None or capture is not None or pcap2csv is not None or csv2sql is not None:
		if info == True:
			display_info()
		elif ip_geo is not None:
			geo_city(ip_geo)
		elif scan is not None:
			portscan(scan)
		elif ping is not None and method == "arp":
			arp_ping(ping)
		elif ping is not None and method == "icmp":
			icmp_ping(ping)
		elif ping is not None and method == "tcp" and port is not None:
			tcp_ping(ping,port)
		elif ping is not None and method == "udp":
			udp_ping(ping,port = 0)
		elif capture == True:
			if packet is not None:
				number_packet = packet
			sniff(filter="ip", prn=handle_packet)
		elif pcap2csv is not None:
			transfer_csv(pcap2csv)
		elif csv2sql is not None:
			transfer_sql(csv2sql)
	else:
		print("\nPlease try again.")
		sys.exit(1)	


if __name__ == "__main__":
	main()
