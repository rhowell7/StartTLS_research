#!/usr/bin/python

# sudo apt-get install python-scapy
# sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

from scapy.all import *
import random
import re

size250 = re.compile('.*?S ?I ?Z ?E.*?', re.DOTALL)
sport = random.randint(1024,65535)
dport = 25
seq = 100
#target = "107.4.83.232" # mail.rosehowell.com
target = "66.196.118.35" # yahoo
ip = IP(dst=target)

print "[1. Get 220 Banner for {}]".format(target)
syn = ip/TCP(sport=sport, dport=dport, flags="S", seq=seq)
synack = sr1(syn, filter="host %s and port %d" % (target, sport)) 

ack = synack.seq + 1
seq = seq + 1

ack1 = ip/TCP(sport=sport, dport=dport, flags="A", seq=seq, ack=ack)
banner220 = sr1(ack1, filter="host %s and port %d" % (target, sport))

ack = ack + len(banner220.payload.payload)
ack2 = ip/TCP(sport=sport, dport=dport, flags="A", seq=seq, ack=ack)
send(ack2)

print "{}".format(banner220.payload.payload) ,

print "[2. Get 250 Extensions for {}]".format(target)
ehlo = IP(dst=target)/TCP(sport=sport,dport=dport,flags="PA",seq=seq,ack=ack)/("EHLO ME\r\n")
extensions = sr1(ehlo, filter="port %d" %(sport))  # the next packet might be an ACK
print "sr1() for extensions using port {}".format(sport)

print extensions.summary()
print extensions[0].summary()
print extensions[1].summary()
print extensions[2].summary()

print '\n'				
for x in range(1, 5):
	print "\nAttempt %d/5: " % x
	print extensions.summary()
	print extensions[0].summary()
	
	try:
		ext_packet = str(extensions[0].payload.payload.payload)
		# print str(extensions[0].payload.payload.payload)
	except IndexError as e:
		print "IndexError"
		continue

	if size250.match(ext_packet):
		print 'Packet contains 250-SIZE. Got extensions, OK to proceed.'
		break

	else:
		extensions = sniff(filter="port %d"%(sport), count=1, timeout=5)
		print "\nSniffing for extensions using port %d"%(sport)


print "[3. Closing Connection to {}]".format(target)
packet = IP(dst=target)/TCP(sport=sport,dport=dport,flags="R", seq=141)
send(packet) # Send reset packet