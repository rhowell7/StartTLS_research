# lines 50-51
#        data=str(pack[Raw])
#        self.ack+=len(data)
# https://github.com/camdroid/Firewalkers/blob/master/client/packetEngine.py

#!/usr/bin/python

# When scapy sends a SYN packet, the kernel doesn't see it. So when the kernel 
# receives a SYN-ACK back, it typically sends a RST packet, because it didn't
# initiate the conversation.  To supress these RST packets from leaving our box:
# sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

from scapy.all import *

# Known good servers:
#target = "10.0.0.109"      # mail.rosehowell.com internal
#target = "107.4.83.232"    # mail.rosehowell.com external (Michigan)
#target = "173.194.69.26"   # gmail-smtp-in.l.google.com
#target = "41.231.120.150"  # mail.rchowell.net (Tunisia)
#target = "66.196.118.35"   # mta5.am0.yahoodns.net
#target = "65.55.33.135"    # mx1.hotmail.com
target = "141.211.22.134"  # mx1.umich.edu

# Known servers to have an issue:
#target = "128.32.78.14"    # (mx1.ischool.berkeley.edu)
#target = "128.32.78.35"    # (mulberry.ischool.berkeley.edu)
#target = "128.32.80.167"   # (list2.bruinpost.ucla.edu)        # consistent
#target = "131.193.42.60"   # (voyager.ai.uic.edu)
#target = "131.193.46.40"   # (image.ece.uic.edu)
#target = "128.248.41.50"   # (mail.psych.uic.edu)

#target = "174.136.156.52"  # (detroit01.idinteract.com)
#target = "162.247.5.233"   # (mx6.solecistic.com)


starttlsTTL = 45
ehloTTL = 64
ehloTimeout = 1    # some servers can take 5-10 seconds for a 220 EHLO response
dport = 25
sport = random.randint(1024,65535)
#print "source port: {}".format(sport)


#------------------------------------------------------------------------------#
#------------------------Establish the TCP Connection--------------------------#
#------------------------------------------------------------------------------#

print '# 1. OUT: Open the connection; send a SYN packet to target on port 25.'
ip = IP(dst=target)
SYN = TCP(sport=sport, dport=dport, seq=100)
SYNACK = sr1(ip/SYN)

print '# 2. IN: Receieve the SYN/ACK'
#print SYNACK[0].summary()

print '# 3. OUT: Send an ACK, with the correct ACK sequence number'
print 'sequence number {}'.format(SYNACK.seq)
my_ack = SYNACK.seq + 1
ACK = TCP(sport=sport, dport=dport, flags="A", seq=101, ack=my_ack)
resp220 = sr1(ip/ACK)

print '# 4. IN: Receive the 220 banner'
#print resp220[0].summary()

print '# 5. OUT: ACK the 220 banner'
# TODO: Magic number -39 = needed to send the correct ACK sequence
#       Most likely to subtract the size of the header, so we only add the 
#       size of the previous packet's payload to the ACK
print 'sequence number {}'.format(resp220.seq)
#my_ack = SYNACK.seq + len(resp220) - 39
#my_ack = resp220.seq
my_ack += len(resp220.payload.payload)
#print "dir of resp220.payload: {}".format(dir(resp220.payload))
print "summary of resp220: "
print resp220.summary()
ACK = TCP(sport=sport, dport=dport, flags="A", seq=101, ack=my_ack)
send(ip/ACK)


#------------------------------------------------------------------------------#
#----------------------Send Ehlo, Receive Extensions---------------------------#
#------------------------------------------------------------------------------#

print '# 6. OUT: Send EHLO ME'
ehlo = IP(dst=target, ttl=ehloTTL)/TCP(sport=sport,dport=dport,flags="PA",seq=101,ack=my_ack)/("EHLO ME\r\n")
ehloACK = sr1(ehlo)
extensions = sniff(filter="host {}".format(target), count=1)
data=str(extensions[Raw])
#self.ack+=len(data)
print 'length of the raw extensions {}'.format(len(data))


print '# 7. IN: Server ACKs the EHLO, we saved as ehloACK' 
#print ehloACK[0].summary()

print '# 8. IN: extensions[0].payload.payload.payload should now be their service extensions:'
print 'extensions[0].payload.payload.payload: {}'.format(extensions[0].payload.payload.payload)
#print extensions.summary()
#print str(extensions.load)

print '# 9. OUT: ACK the extensions'
#print "dir of tcp packet payload: {}".format(dir(extensions[0].payload.payload.payload))
#print "payload type: {}".format(type(extensions[0].payload.payload.payload))
ip_packet = extensions[0].payload
#print "ip packet payload length: {}".format(len(ip_packet.payload))
#print "tcp packet payload length: {}".format(len(tcp_packet.payload))
print "length of ehloACK.payload.payload: {}".format(len(ehloACK.payload.payload))
#print "difference (tcp header length): {}".format(len(ip_packet.payload) - len(tcp_packet.payload))
#print "possible ack: {}".format(SYNACK.seq + len(tcp_packet.payload))

tcp_packet = extensions[0].payload.payload
#print "tcp packet: {}".format(tcp_packet)
#print "tcp packet dir: {}".format(dir(tcp_packet))
data_from_sniffed_packet = extensions[0].payload.payload.payload
#print "length: {}".format(len(data_from_sniffed_packet))
#print "data: {}".format(data_from_sniffed_packet)

if (len(ehloACK.payload.payload) > 10):
    my_ack = my_ack + len(ehloACK.payload.payload)
else:
    my_ack = my_ack + len(tcp_packet.payload)

ACK = TCP(sport=sport, dport=dport, flags="A", seq=110, ack=my_ack)
send(ip/ACK)


#------------------------------------------------------------------------------#
#------------------------Attempt to Start TLS----------------------------------#
#------------------------------------------------------------------------------#

print '# 10. OUT: Send STARTTLS'
packet = IP(dst=target, ttl=starttlsTTL)/TCP(sport=sport,dport=dport,flags="PA",seq=110,ack=my_ack)/("STARTTLS\r\n")
TLSbanner = sr1(packet)


print '# 11. IN: Receive banner'
print TLSbanner[0].summary()
print 'TLSbanner.load: {}'.format(TLSbanner.load)


# Print results
ip_src=TLSbanner[IP].src
print '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
print "Banner received from {}".format(str(ip_src)) + ': {}'.format(TLSbanner.load)
#print "TLSbanner dir: {}".format(dir(TLSbanner))
f = open('results.{}.txt'.format(str(target)), 'a')
f.write('Hop {}: '.format(str(starttlsTTL)) + 'Banner received from {}'.format(str(ip_src)) + ': {}'.format(TLSbanner.load))
f.close()


print '# 12. OUT: ACK the 220 banner'
my_ack = my_ack + len(TLSbanner[0].payload.payload)
ACK = TCP(sport=sport, dport=dport, flags="A", seq=120, ack=my_ack)
send(ip/ACK)


#------------------------------------------------------------------------------#
#--------------------Close the Connection Gracefully---------------------------#
#------------------------------------------------------------------------------#

print '# 13. OUT: Close the connection, send FIN/ACK'
FINpacket = IP(dst=target)/TCP(sport=sport,dport=dport,flags="FA",seq=120, ack=my_ack)
FINACK = sr1(FINpacket)

print '# 14. Server responds with another FIN/ACK'
#print FINACK[0].summary()

print '# 15. We ACK their last FIN/ACK'
packet = IP(dst=target)/TCP(sport=sport,dport=dport,flags="A",seq=121, ack=my_ack+1)
send(packet)


'''
#------------------------------------------------------------------------------#
#------------------------Force Close the Connection----------------------------#
#------------------------------------------------------------------------------#
print 'OUT: Close the connection, send RST'
RESpacket = IP(dst=target)/TCP(sport=sport,dport=dport,flags="R",seq=121, ack=my_ack)
send(RESpacket)
send(RESpacket)
'''
