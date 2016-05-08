#!/usr/bin/python

# sudo apt-get install python-scapy
# sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

from scapy.all import *
import re
import sys
import json
import pprint
import Queue
import threading
import time


# number of hops away to start the StartTLS traceroute
tlsTTL = 4
size250 = re.compile('.*?S ?I ?Z ?E.*?', re.DOTALL)
Hello = re.compile('.*H ?e ?l ?l ?o.*', re.IGNORECASE)
two50 = re.compile('.*2 ?5 ?0.*', re.IGNORECASE)
win = re.compile('.*S ?T ?A ?R ?T ?T ?L ?S.*', re.IGNORECASE | re.DOTALL | re.MULTILINE)
errorXXXX = re.compile('.*X ?X ?X ?X.*', re.IGNORECASE)
timeout220 = 4
timeoutTTL = 1

"""
Sends a STARTTLS request to mail servers
"""

class WorkerThread(threading.Thread) :
	def __init__(self, queue, tid) :
		threading.Thread.__init__(self)
		self.queue = queue
		self.tid = tid
		self.seq = 100
		self.ack = 0
		self.dport = 25
		self.sport = random.randint(1024,65535)
		# self.target = targetIP
		self.ehloTTL = 64
		print "Worker %d Reporting for Service!" %self.tid

	##############################################################################################
	#def get220banner(self):
	def run(self) :
		total_ips = 0
		while True :
			target = 0
			try :
				target = self.queue.get(timeout=1)
				print "Got target IP: {}".format(target)
			except  Queue.Empty :
				print "Worker %d exiting. Scanned %d ports ..." % (self.tid, total_ips)
                		return
            		# Begin scanning
            		# Using scapy
			print "[1. Get 220 Banner for {}]".format(target)
			self.sport = random.randint(1024,65535)		# needs a new port/socket for each loop
			ip = IP(dst=target)
			syn = ip/TCP(sport=self.sport, dport=self.dport, flags="S", seq=self.seq)
			synack = sr1(syn, verbose=0, timeout=timeout220)
			if synack is None:
				print "No response to SYN from {} after {} seconds  :(".format(target, timeout220)
				print "[Continue]\n\n"
				return 1

			self.ack = synack.seq + 1
			self.seq = self.seq + 1

			ack = ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack) #101
			banner220 = sr1(ack, verbose=0, timeout=timeout220)
			if banner220 is None:
				print "No 220 banner received from {} after {} seconds :(".format(target, timeout220)
				print "[Continue]\n\n"
				return 1

			self.ack = self.ack + len(banner220.payload.payload)
			ack = ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack) #101
			send(ack, verbose=0)

			print "{}".format(banner220.payload.payload) ,
			# print "[Got 220 Banner for {}]".format(target)
			#return 0
			
			##############################################################################################
			#def get250extensions(self):
			print "[2. Get 250 Extensions for {}]".format(target)
			# print target
			ehlo = IP(dst=target, ttl=self.ehloTTL)/TCP(sport=self.sport,dport=self.dport,flags="PA",seq=self.seq,ack=self.ack)/("EHLO ME\r\n") #101
			# extensions = sr1(ehlo, verbose=0, timeout=5)  ## NO! the next packet is an ACK. need to sniff.

			send(ehlo, verbose=0)
			extensions = sniff(filter="host {}".format(target), count=1, timeout=5)
			
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
				elif errorXXXX.match(ext_packet):
					print "Packet contains XXXX Error: {}".format(ext_packet) ,
					print 'Sending HELO instead'

					# Ack the 500-error
					try:
						tcp_packet = extensions[0].payload.payload
					except IndexError as e:
						print "IndexError"
					self.ack = self.ack + len(tcp_packet.payload)
					self.seq = self.seq + 9
					ip = IP(dst=target)
					ack = ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack) #110?
					send(ack, verbose=0)
					print "Sent ACK line 100"

					# Send HELO instead
					helo = IP(dst=target, ttl=self.ehloTTL)/TCP(sport=self.sport,dport=self.dport,flags="PA",seq=self.seq,ack=self.ack)/("HELO ME\r\n") #110
					extensions = sr1(helo, verbose=0, timeout=5)
					try:
						ext_packet = str(extensions[0].payload.payload)
					except TypeError as e:
						print "TypeError:  Remote server may be graylisting us"
						return 1
					
					print "Sent HELO, got {}".format(ext_packet) ,
					# if EHLO fails, but HELO works, they won't send 250-SIZE, so break here??
					if Hello.match(ext_packet):
						print "Matches Hello packet"
						# ACK the Hello-extensions
						try:
							tcp_packet = extensions[0].payload.payload
						except IndexError as e:
							print "IndexError"

						# Ack the Hello packet
						self.ack = self.ack + len(tcp_packet)
						self.seq = self.seq + 9
						ip = IP(dst=target)
						ack = ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack) #110?
						send(ack, verbose=0)
						print "Sent ack of length: {}".format(self.ack)
						print "Sent ACK line 138"

						break

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

					ip = IP(dst=target)
					ack = ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack) #110
					send(ack, verbose=0)
					print "Sent ACK line 158"
					self.ack = self.ack - len(tcp_packet.payload)
					extensions = sniff(filter="host {}".format(target), count=1, timeout=5)
				elif two50.match(ext_packet):
					print "Packet contains 250"
					try:
						tcp_packet = extensions[0].payload.payload
					except IndexError as e:
						print "IndexError"
						continue

					self.ack = self.ack + len(tcp_packet.payload)
					self.seq = self.seq + 9

					ip = IP(dst=target)
					ack = ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack) #110
					send(ack, verbose=0)
					print "Sent ACK line 175"
					self.ack = self.ack - len(tcp_packet.payload)
					extensions = sniff(filter="host {}".format(target), count=1, timeout=5)
				else:
					print "Packet does not contain [SIZE | XXXX | Hello | 250]"
					
					# print ext_packet
					extensions = sniff(filter="host {}".format(target), count=1, timeout=5)

			try:
				tcp_packet = extensions[0].payload.payload
			except IndexError as e:
				print "IndexError"
				print "Could not get 250-Extensions from {}".format(target)
				print "[Return 1]"
				return 1

			self.ack = self.ack + len(tcp_packet.payload)
			self.seq = self.seq + 9

			ip = IP(dst=target)
			ack = ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack) #110
			send(ack, verbose=0)
			print "Sent ACK line 206"

			##############################################################################################
			# def startTLS(self, tlsTTL):
			print "[3. Try StartTLS for {}]".format(target)
			mail_server = {}
			mail_server["target_ip"] = target
			done = re.compile(target)

			for i in range (tlsTTL, 30):
				# result = smtpConnection.startTLS(i)
				ip = IP(dst=target, ttl=i)
				startTLS = ip/TCP(sport=self.sport,dport=self.dport,flags="PA",seq=self.seq,ack=self.ack)/("STARTTLS\r\n") #110
				TLSbanner = sr1(startTLS, verbose=0, timeout=timeoutTTL)

				if TLSbanner is None:
					# No reply
					print "No response to STARTTLS request from hop {} after {} seconds".format(i, timeoutTTL)
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

			print "Dict for {}".format(target)
			pprint.pprint(mail_server, width=1)

			##############################################################################################
			# def closeConnection(self):
			print "[4. Closing Connection to {}]".format(target)
			FINpacket = IP(dst=target)/TCP(sport=self.sport,dport=self.dport,flags="FA",seq=120, ack=self.ack)
			FINACK = sr1(FINpacket, verbose=0, timeout=1)

			packet = IP(dst=target)/TCP(sport=self.sport,dport=self.dport,flags="A",seq=121, ack=self.ack+1)
			send(packet, verbose=0)
			print '\n'

			self.queue.task_done()
            		total_ips += 1


queue = Queue.Queue()

threads = []

for i in range (1, 10):
	print "Creating WorkerThread : %d" %i
	worker = WorkerThread(queue, i)
	worker.setDaemon(True)
	worker.start()
	threads.append(worker)
	print "WorkerThread %d Created!" %i

# for j in range (1, 100):
# 	queue.put(j)
with open('ipAddresses.txt') as inFile:
	for line in inFile:
		target = str(line.rstrip('\n'))
		queue.put(target)

queue.join()

# wait for all threads to exit

for item in threads:
	item.join()

print "Scanning Complete!"



# with open('ipAddresses.txt') as inFile:
	
# 	for line in inFile:
# 		target = str(line.rstrip('\n'))
# 		win = re.compile('.*START ?TLS*', re.IGNORECASE)
# 		done = re.compile(target)
# 		lose = re.compile("5\d\d*")
# 		result = "test"
# 		done = 0


# 		smtpConnection = WorkerThread(target)
# 		done = smtpConnection.get220banner()
# 		if done is 1:
# 			# List the fails
# 			print 'Error: {} did not respond with their 220 Banner'.format(target)
# 			continue
			

# 		done = smtpConnection.get250extensions()
# 		if done is 1:
# 			smtpConnection.closeConnection()
# 			# List the fails
# 			print 'Error: {} did not respond with their 250 Extensions'.format(target)
# 			continue
# 		smtpConnection.startTLS(tlsTTL)
# 		smtpConnection.closeConnection()
