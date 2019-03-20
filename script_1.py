from scapy.all import *



def byMac(packet):
	if(sys.argv[1] == packet.addr2):
		print(sys.argv[1] + " is nearby \n")
	else:
		return

# We sniff the wlan0mon in order to find if a MAC adress is near
# The prn argument is the method we use to print a message  if we get a wanted packet
if __name__ == "__main__":
	sniff(iface="wlan0mon",  prn=byMac)
