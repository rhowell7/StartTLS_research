#!/usr/bin/python

import socket
import sys
import thread
import atexit
import signal
import struct

ttl = 25
maxTTL = 45
bufferSize = 1024
icmp = socket.getprotobyname('icmp')


# mailserver = 'mail.rchowell.net'
# mailserver = '41.231.120.150'
mailserver = '128.32.80.167'
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
# while True:
    # print "ping"
    
    # # mySocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    # mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
    # print "ping2"    
    # mySocket.send(startTLS)
    # print "ping3"

    # recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    # print "ping4"
    # recv_socket.bind(("", localPort))
    # print "ping5"
    # _, curr_addr = recv_socket.recvfrom(bufferSize)

    # print "ping6"
    # # currAddr = currAddr[0]
    # print currAddr
    # print tlsBanner
    # if currAddr == mailserver or ttl > maxTTL:
    #     break
    # ttl += 1

dest_addr = mailserver
port = localPort
max_hops = 26
icmp = socket.getprotobyname('icmp')
# udp = socket.getprotobyname('udp')
# smtp = socket.getprotobyname('smtp')
# tcp = socket.getprotobyname('tcp')
ip = socket.getprotobyname('ip')

ttl = 4
while True:
    recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    recv_socket.settimeout(2.0)
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, ip)
    send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    recv_socket.bind(("", port))
    send_socket.sendto("STARTTLS", (mailserver, port))
    curr_addr = None
    curr_name = None
    try:
        tls_response, curr_addr = recv_socket.recvfrom(512)
        curr_addr = curr_addr[0]
        try:
            curr_name = socket.gethostbyaddr(curr_addr)[0]
        except socket.error:
            curr_name = curr_addr
    except socket.error:
        pass
    finally:
        send_socket.close()
        recv_socket.close()

    if curr_addr is not None:
        curr_host = "%s (%s)" % (curr_name, curr_addr)
    else:
        curr_host = "* * *"
    # print "%d\t%s" % (ttl, curr_host)
    print "ttl: ",
    print ttl
    print "tls_response: ",
    print tls_response
    # print "tls_response[0]: ",
    # print tls_response[0]
    # print "tls_response[1]: ",
    # print tls_response[1]
    # print "tls_response[2]: ",
    # print tls_response[2]


    ttl += 1
    if curr_addr == dest_addr or ttl > max_hops:
        break

# Close the connection
def closeSocket(socket):
    socket.close()
    print "Closing socket"
atexit.register(closeSocket, mySocket)
