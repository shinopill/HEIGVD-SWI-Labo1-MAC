
from scapy.all import sniff, Dot11

import requests
VENDOR = 0
SSIDS = 1
MAC_URL = 'http://macvendors.co/api/'

def request_mac(mac):
	r = requests.get(MAC_URL + mac)
	try:
		company = r.json()['result']['company']
		return company
	except:
		return 'Unknown'
	
	

device_detected = set() #Devices already detected
d = {} #Dictionary of all known constructors

def handle_packet(packet):
	if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 4: #Probe Requests
		macAddress = packet.addr2.upper()
		SSID = packet.info if packet.info != '' else 'Unknown'
		device_detected.add(macAddress) #Add to detected devices
		if macAddress not in d:
			vendor = request_mac(macAddress)
			d[macAddress] = [vendor, []]
			d[macAddress][SSIDS].append(SSID)
			print(macAddress + ' (' + d[macAddress][VENDOR] + ') ' + '- ' + SSID)
		elif SSID not in d[macAddress][SSIDS]:
			d[macAddress][SSIDS].append(SSID)
			AllSSID = ''
			for s in d[macAddress][SSIDS] :
				AllSSID = AllSSID + s + ', '
			print(macAddress.encode('utf-8') + ' (' + d[macAddress][VENDOR].encode('utf-8') + ') ' + '- ' + AllSSID.encode('utf-8'))

def main():	
	import argparse
	parser = argparse.ArgumentParser()
	parser.add_argument('--interface', '-i', default='wlan0mon', help='monitor mode enabled interface')
	args = parser.parse_args()
	sniff(iface=args.interface, prn=handle_packet) #start sniffing
if __name__ == '__main__':
	main()
