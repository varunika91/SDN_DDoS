
import sys
from socket import * 

HOST = '10.0.1.2'
PORT = 80
ADDR = (HOST,PORT)
BUFSIZE = 2048

message='/pp.txt'

client = socket(AF_INET,SOCK_STREAM)
client.connect((ADDR))

client.send("GET /%s HTTP/1.1\r\n" % message)

data = client.recv(BUFSIZE)
x = data
if "Authenticate" in x:
	print data	
	inp = raw_input()
	client.send( "%s" % inp)

	data = client.recv(BUFSIZE)
	if ("Authentication Failed" in data):
		print data
		sys.exit(0)
	else:
		pass			
else:
	pass
data = data.rstrip()
print data

client.close()
