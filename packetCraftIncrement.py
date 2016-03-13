#!/usr/bin/python

# sudo apt-get install python-scapy
# sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

from scapy.all import *
import re
import sys
import json
import pprint

tlsTTL = 3
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
		self.seq = 100
		self.ack = 0
		self.dport = 25
		self.sport = random.randint(1024,65535)
		self.target = targetIP
		self.ehloTTL = 64

	def get220banner(self):
		print "[1. Get 220 Banner for {}]".format(self.target)
		self.sport = random.randint(1024,65535)		# needs a new port/socket for each loop
		ip = IP(dst=self.target)
		syn = ip/TCP(sport=self.sport, dport=self.dport, flags="S", seq=self.seq)
		synack = sr1(syn, verbose=0, timeout=10)
		if synack is None:
			print "No response to SYN from {}  :(".format(self.target)
			print "[Continue]\n\n"
			return 1

		self.ack = synack.seq + 1
		self.seq = self.seq + 1

		ack = ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack) #101
		banner220 = sr1(ack, verbose=0, timeout=11)
		if banner220 is None:
			print "No 220 banner received from {}  :(".format(self.target)
			print "[Continue]\n\n"
			return 1

		self.ack = self.ack + len(banner220.payload.payload)
		ack = ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack) #101
		send(ack, verbose=0)

		print "{}".format(banner220.payload.payload) ,
		# print "[Got 220 Banner for {}]".format(self.target)
		return 0
		

	def get250extensions(self):
		print "[2. Get 250 Extensions for {}]".format(self.target)
		# print self.target
		ehlo = IP(dst=self.target, ttl=self.ehloTTL)/TCP(sport=self.sport,dport=self.dport,flags="PA",seq=self.seq,ack=self.ack)/("EHLO ME\r\n") #101
		# extensions = sr1(ehlo, verbose=0, timeout=5)
		send(ehlo, verbose=0)
		extensions = sniff(filter="host {}".format(self.target), count=1, timeout=5)
		
		for x in range(1, 5):
			print "Attempt %d/5: " % x ,
			try:
				ext_packet = str(extensions[0].payload.payload.payload)
			except IndexError as e:
				print "IndexError"
				continue

			if size250.match(ext_packet):
				print 'Packet contains 250-SIZE. Got extensions, OK to proceed.'
				break
			elif error500.match(ext_packet):
				print "Packet contains 500 Error: {}".format(ext_packet) ,
				print 'Sending HELO instead'

				# Ack the 500-error
				# self.seq = self.seq + 9
				# ip = IP(dst=self.target)
				# ack = ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack) #110?
				# send(ack, verbose=0)
				try:
					tcp_packet = extensions[0].payload.payload
				except IndexError as e:
					print "IndexError"
				self.ack = self.ack + len(tcp_packet.payload)
				self.seq = self.seq + 9
				ip = IP(dst=self.target)
				ack = ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack) #110?
				send(ack, verbose=0)

				# Send HELO instead
				helo = IP(dst=self.target, ttl=self.ehloTTL)/TCP(sport=self.sport,dport=self.dport,flags="PA",seq=self.seq,ack=self.ack)/("HELO ME\r\n") #110
				extensions = sr1(helo, verbose=0, timeout=5)
				ext_packet = str(extensions[0].payload.payload)
				
				print "Sent HELO, got {}".format(ext_packet) ,
				# if EHLO fails, but HELO works, they won't send 250-SIZE, so break here
				if Hello.match(ext_packet):
					print "Matches Hello packet"
					# ACK it
					try:
						tcp_packet = extensions[0].payload.payload
					except IndexError as e:
						print "IndexError"
					self.ack = self.ack + len(tcp_packet.payload)
					self.seq = self.seq + 9
					ip = IP(dst=self.target)
					ack = ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack) #110?
					send(ack, verbose=0)

					break

				continue
			elif Hello.match(ext_packet):
				# tcp_packet = extensions[0].payload.payload  # IndexError
				print "Packet contains Hello"
				try:
					tcp_packet = extensions[0].payload.payload
				except IndexError as e:
					print "IndexError"
					continue

				self.ack = self.ack + len(tcp_packet.payload)
				self.seq = self.seq + 9

				ip = IP(dst=self.target)
				ack = ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack) #110
				send(ack, verbose=0)
				self.ack = self.ack - len(tcp_packet.payload)
				extensions = sniff(filter="host {}".format(self.target), count=1, timeout=5)
			elif two50.match(ext_packet):
				print "Packet contains 250"
				# tcp_packet = extensions[0].payload.payload  # IndexError
				try:
					tcp_packet = extensions[0].payload.payload
				except IndexError as e:
					print "IndexError"
					continue

				self.ack = self.ack + len(tcp_packet.payload)
				self.seq = self.seq + 9

				ip = IP(dst=self.target)
				ack = ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack) #110
				send(ack, verbose=0)
				self.ack = self.ack - len(tcp_packet.payload)
				extensions = sniff(filter="host {}".format(self.target), count=1, timeout=5)
			else:
				print "Packet does not contain SIZE or 500"
				#print ext_packet
				extensions = sniff(filter="host {}".format(self.target), count=1, timeout=5)

		# tcp_packet = extensions[0].payload.payload
		try:
			tcp_packet = extensions[0].payload.payload
		except IndexError as e:
			print "IndexError"
			print "Could not get 250-Extensions from {}".format(self.target)
			print "[Continue]"
			return 1

		self.ack = self.ack + len(tcp_packet.payload)
		self.seq = self.seq + 9

		ip = IP(dst=self.target)
		ack = ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack) #110
		send(ack, verbose=0)

		# print "{}".format(extensions[0].payload.payload.payload)
		# print "[Got 250 Extensions for {}]".format(self.target)
		return 0
		
	def startTLS(self, tlsTTL):
		print "[3. Try StartTLS for {}]".format(self.target)
		mail_server = {}
		mail_server["target_ip"] = self.target
		done = re.compile(target)
		# ip = IP(dst=self.target, ttl=tlsTTL)
		# startTLS = ip/TCP(sport=self.sport,dport=self.dport,flags="PA",seq=110,ack=self.ack)/("STARTTLS\r\n")
		# TLSbanner = sr1(startTLS)
		# send(startTLS)
		# TLSbanner = sniff(filter="host {}".format(self.target), count=1)

		for i in range (4, 30):
			# result = smtpConnection.startTLS(i)
			ip = IP(dst=self.target, ttl=i)
			startTLS = ip/TCP(sport=self.sport,dport=self.dport,flags="PA",seq=self.seq,ack=self.ack)/("STARTTLS\r\n") #110
			TLSbanner = sr1(startTLS, verbose=0, timeout=4)

			# send(startTLS)
			# TLSbanner = sniff(filter="host {}".format(self.target), count=1)

			# print TLSbanner[0].getlayer(IP).src
			# print TLSbanner[0][IP].src
			# serverIP = str(TLSbanner[0].getlayer(IP).src)
			# serverIP = str(TLSbanner[0].src)
			if TLSbanner is None:
				# No reply
				print "No response to STARTTLS request from hop %d" % i
				continue
			elif done.match(TLSbanner.src):
				print "%d hops away: " % i , TLSbanner.src ,
				print "Reached the Target IP"
				try:
					print 'returned: {}'.format(TLSbanner.load) ,
					mail_server["response_from_target"] = TLSbanner.load
					break
			 	except AttributeError as e:
			 		print "returned: AttributeError. Trying once more.."
			 		i = i-1

				# break
			else:
				print "%d hops away: " % i , TLSbanner.src , 
				mail_server["ICMP_response_IP"] = TLSbanner.src
				# print '{}'.format(TLSbanner.load)
				try:
					print 'returned: {}'.format(TLSbanner.load) ,
					mail_server["ICMP_response_payload"] = TLSbanner.load
			 	except AttributeError as e:
			 		print "returned: AttributeError"
			 		mail_server["ICMP_response_payload"] = "ICMP_response_did_not_contain_payload"

		print "Dict for {}".format(self.target)
		pprint.pprint(mail_server, width=1)

		# self.ack = self.ack + len(TLSbanner[0].payload.payload)
		# ack = TCP(sport=self.sport, dport=self.dport, flags="A", seq=120, ack=self.ack)
		# send(ip/ack)

		# print '[Got STARTTLS Response]'
		# print '{}'.format(TLSbanner.load)
		
		# ip_src=TLSbanner[IP].src
		# f = open('results.{}.txt'.format(str(self.target)), 'a')
		# f.write('Hop {}: '.format(str(tlsTTL)) + 'Banner received from {}'.format(str(ip_src)) + ': {}'.format(TLSbanner.load))
		# f.close()
		# TODO: Print output to JSON dict
		# create object called scan<targetIP>?  New dict for each target IP?
		# scan = {}
		# scan['targetIP'] = self.target
		# scan['hop'] = tlsTTL
		# if error500.match(str(TLSbanner)):
		# 	scan['responseFrom'] = ip_src
		# 	scan['error'] = TLSbanner.load
		# elif win.match(str(TLSbanner)):
		# 	scan['responseFrom'] = ip_src
		# 	scan['pingPacket'] = TLSbanner.load
		# else:
			# startTLS(tlsTTL)	# Make this a recursive call?


		# return str(TLSbanner.load)
		# return str(TLSbanner.src)

	def closeConnection(self):
		print "[4. Closing Connection to {}]".format(self.target)
		FINpacket = IP(dst=self.target)/TCP(sport=self.sport,dport=self.dport,flags="FA",seq=120, ack=self.ack)
		FINACK = sr1(FINpacket, verbose=0, timeout=1)

		packet = IP(dst=self.target)/TCP(sport=self.sport,dport=self.dport,flags="A",seq=121, ack=self.ack+1)
		send(packet, verbose=0)
		print '\n'


with open('ipAddresses.txt') as inFile:
	for line in inFile:
		target = str(line.rstrip('\n'))
		#tlsTTL = 20						# TODO: Optimal TTL to start with based on traceroute?
		win = re.compile('.*START ?TLS*', re.IGNORECASE)
		done = re.compile(target)
		lose = re.compile("5\d\d*")
		result = "test"
		done = 0


		smtpConnection = PacketCraft(target)
		done = smtpConnection.get220banner()
		if done is 1:
			continue
		done = smtpConnection.get250extensions()
		if done is 1:
			smtpConnection.closeConnection()
			continue
		smtpConnection.startTLS(1)
		smtpConnection.closeConnection()

		# for i in range (4, 28):
		# 	result = smtpConnection.startTLS(i)
		# 	if result is None:
		# 		# No reply
		# 		break
		# 	elif done.match(result):
		# 		print "done"
		# 		smtpConnection.closeConnection()
		# 		break
		# 	else:
		# 		print "%d hops away: " % i , result

		# try:
		# 	result = smtpConnection.startTLS(tlsTTL)
		# except IndexError as e:			# IndexError when the TTL is too short
		# 	print "IndexError"

		# while not lose.match(result):
		# 	tlsTTL = tlsTTL - 1
		# 	# smtpConnection.get220banner()
		# 	# smtpConnection.get250extensions()
		# 	try:
		# 		result = smtpConnection.startTLS(tlsTTL)
		# 	except IndexError as e:
		# 		print "IndexError"

		# 	if win.match(result):
		# 		print "win"
		# 		#smtpConnection.closeConnection()
		# 		# break			# all good servers will end up in this case, along with the bad nodes that strip the STARTTLS
		# 	if lose.match(result):
		# 		print "went too far"
		# 		break			# no good servers will end up in this case, only 500-level errors here, nodes that have already been stripped
