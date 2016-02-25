#!/usr/bin/python

# When scapy sends a SYN packet, the kernel doesn't see it. So when the kernel 
# receives a SYN-ACK back, it typically sends a RST packet, because it didn't
# initiate the conversation.  To supress these RST packets from leaving our box:
# sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
# Install Scapy
# sudo apt-get install python-scapy

from scapy.all import *
import re
import sys
# import ipaddress
import json

size250 = re.compile('.*?SIZE.*?', re.DOTALL)
Hello = re.compile('.*Hello.*', re.IGNORECASE)
two50 = re.compile('250.*', re.IGNORECASE)
win = re.compile('.*START ?TLS.*', re.IGNORECASE | re.DOTALL | re.MULTILINE)
error500 = re.compile('500.*', re.IGNORECASE)

"""
Sends a STARTTLS request to mail servers
"""

class PacketCraft:
	def __init__(self, targetIP):
		#self.seq = 100
		self.ack = 0
		self.dport = 25
		self.sport = random.randint(1024,65535)
		self.target = targetIP
		#self.starttlsTTL = 30
		self.ehloTTL = 64

	def get220banner(self):
		print '[Get 220 Banner]'
		print self.target
		self.sport = random.randint(1024,65535)		# needs a new port/socket for each loop
		ip = IP(dst=self.target)
		syn = ip/TCP(sport=self.sport, dport=self.dport, flags="S", seq=100)
		synack = sr1(syn)

		self.ack = synack.seq + 1
		ack = ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=101, ack=self.ack)
		banner220 = sr1(ack)

		self.ack = self.ack + len(banner220.payload.payload)
		ack = ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=101, ack=self.ack)
		send(ack)

		#self.seq = synack.ack

		print '[Got 220 Banner]'
		print "{}".format(banner220.payload.payload)

	def get250extensions(self):
		print '[Get 250 Extensions]'
		print self.target
		ehlo = IP(dst=self.target, ttl=self.ehloTTL)/TCP(sport=self.sport,dport=self.dport,flags="PA",seq=101,ack=self.ack)/("EHLO ME\r\n")
		send(ehlo)
		extensions = sniff(filter="host {}".format(self.target), count=1)
		

		for x in range(0, 4):
			ext_packet = str(extensions[0].payload.payload.payload)
			if size250.match(ext_packet):
				print 'Packet contains 250-SIZE'
				break
			elif error500.match(ext_packet):
				print 'Packet contains 500'
				break
			elif Hello.match(ext_packet):
				tcp_packet = extensions[0].payload.payload
				self.ack = self.ack + len(tcp_packet.payload)

				ip = IP(dst=self.target)
				ack = ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=110, ack=self.ack)
				send(ack)
				self.ack = self.ack - len(tcp_packet.payload)
				extensions = sniff(filter="host {}".format(self.target), count=1)
			else:
				print "Packet does not contain SIZE or 500"
				#print ext_packet
				extensions = sniff(filter="host {}".format(self.target), count=1)

		tcp_packet = extensions[0].payload.payload
		self.ack = self.ack + len(tcp_packet.payload)

		ip = IP(dst=self.target)
		ack = ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=110, ack=self.ack)
		send(ack)



		print '[Got 250 Extensions]'
		print "{}".format(extensions[0].payload.payload.payload)

	def startTLS(self, tlsTTL):
		print '[Try StartTLS]'
		ip = IP(dst=self.target, ttl=tlsTTL)
		startTLS = ip/TCP(sport=self.sport,dport=self.dport,flags="PA",seq=110,ack=self.ack)/("STARTTLS\r\n")
		TLSbanner = sr1(startTLS)

		self.ack = self.ack + len(TLSbanner[0].payload.payload)
		ack = TCP(sport=self.sport, dport=self.dport, flags="A", seq=120, ack=self.ack)
		send(ip/ack)

		print '[Got STARTTLS Response]'
		print '{}'.format(TLSbanner.load)
		
		ip_src=TLSbanner[IP].src
		f = open('results.{}.txt'.format(str(self.target)), 'a')
		f.write('Hop {}: '.format(str(tlsTTL)) + 'Banner received from {}'.format(str(ip_src)) + ': {}'.format(TLSbanner.load))
		f.close()
		# TODO: Print output to JSON dict
		

		

		return str(TLSbanner.load)

	def closeConnection(self):
		FINpacket = IP(dst=self.target)/TCP(sport=self.sport,dport=self.dport,flags="FA",seq=120, ack=self.ack)
		FINACK = sr1(FINpacket)

		packet = IP(dst=self.target)/TCP(sport=self.sport,dport=self.dport,flags="A",seq=121, ack=self.ack+1)
		send(packet)



with open('ipAddresses.txt') as inFile:
	for line in inFile:
		target = str(line.rstrip('\n'))
		tlsTTL = 5						# TODO: Optimal TTL to start with based on traceroute?
		win = re.compile('.*START ?TLS*', re.IGNORECASE)
		lose = re.compile("5\d\d*")
		result = "test"

		smtpConnection = PacketCraft(target)
		smtpConnection.get220banner()
		smtpConnection.get250extensions()
		try:
			result = smtpConnection.startTLS(tlsTTL)
		except IndexError as e:			# IndexError when the TTL is too short
			print "IndexError"

		while not lose.match(result):
			tlsTTL = tlsTTL - 1
			smtpConnection.get220banner()
			smtpConnection.get250extensions()
			try:
				result = smtpConnection.startTLS(tlsTTL)
			except IndexError as e:
				print "IndexError"

			if win.match(result):
				print "win"
				#smtpConnection.closeConnection()
				# break			# all good servers will end up in this case, along with the bad nodes that strip the STARTTLS
			if lose.match(result):
				print "went too far"
				break			# no good servers will end up in this case, only 500-level errors here, nodes that have already been stripped
