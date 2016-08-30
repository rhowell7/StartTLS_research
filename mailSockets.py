#!/usr/bin/python

import socket
import sys
import thread
import atexit
import signal
import struct

ttl = 4
maxTTL = 45
bufferSize = 1024
icmp = socket.getprotobyname('icmp')
# mailserver = '41.231.120.150'
mailserver = '128.32.80.167'


# Initialize the connection
mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
mySocket.connect((mailserver, 25))
recv220 = mySocket.recv(bufferSize)
print recv220
localPort = int(mySocket.getsockname()[1])
# print localPort
if recv220[:3] != '220':
    print '220 reply not received from server {}'.format(mailserver)
# mySocket.bind(("", localPort))


# Send EHLO and print server response
ehlo = 'ehlo me\r\n'
mySocket.send(ehlo)
recv250 = mySocket.recv(bufferSize)
print recv250
if recv250[:3] != '250':
    print '250 extensions not received from server'


# Send STARTTLS
startTLS = 'STARTTLS\r\n'
dest_addr = mailserver
port = localPort
max_hops = 26
icmp = socket.getprotobyname('icmp')
ip = socket.getprotobyname('ip')

while True:
    recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    recv_socket.settimeout(2.0)
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, ip)
    send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    recv_socket.bind(("", port))
    send_socket.sendto("STARTTLS", (mailserver, port))
    curr_addr = None
    try:
        tls_response, curr_addr = recv_socket.recvfrom(512)
        curr_addr = curr_addr[0]
    except socket.error:
        pass
    finally:
        send_socket.close()
        recv_socket.close()

    if curr_addr is None or ttl > max_hops:
        # reached the destination, no longer receiving ICMP packets, accept a tcp/ip
        mySocket.send(startTLS)
        recvTLS = mySocket.recv(bufferSize)
        print "{} hops: Reached {}".format(ttl, dest_addr)
        print "Reached the destination server"
        print "data: {}".format(recvTLS)
        break

    print "{} hops: Reached {}".format(ttl, curr_addr)

    """Parse ICMP packet and return an instance of Packet"""
    tls_response = tls_response[20:]
    string_len = len(tls_response) - 4 # Ignore IP header
    pack_format = "!BBH"
    if string_len:
        pack_format += "%ss" % string_len
    unpacked_packet = struct.unpack(pack_format, tls_response)
    packetType, code, checksum = unpacked_packet[:3]
    try:
        data = unpacked_packet[3]
        # print "packetType: {}".format(packetType)  # should be 11 (timeout)
        data = data[32:]
        print "data: {}".format(data)
    except IndexError:
        data = None
        print "IndexError"
    # print dir(tls_response)
    # print type(tls_response)

    ttl += 1

# Close the connection
def closeSocket(socket):
    socket.close()
    print "Closing socket"
atexit.register(closeSocket, mySocket)