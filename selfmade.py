import time, os, sys, string, threading, math, random
from socket import * 
import os
import thread

class Server():
  def __init__(self, host, port):
    self.host = host
    self.port = port

    self.h_tokens = ["/cc.txt","/dd.txt","/ee.txt"]
    self.blacklist = {}

 
    self.ddos_detected = 0
    self.captcha_mode = 0
    self.ddos_count = 0

    #Creating socket object
    self.serv = socket(AF_INET,SOCK_STREAM)
    
    #Creating socket for attack message
    self.attack = socket(AF_INET,SOCK_STREAM)
 
    #bind socket to address
    self.serv.bind((self.host, self.port))
    self.attack.bind((self.host, 3000))

    #listen 
    self.attack.listen(5)
    self.serv.listen(5) #Setting up the max number of connections we allow as 2, since we want this to be a weak server
    print 'Server up and running! Listening for incoming connections... and attack msg from controller'

  def acceptConnections(self):
    print "listening from client"
    conn, addr = self.serv.accept()
    pid = os.fork()
    if pid == 0:
      serv.close()
      self.handle_request(conn,addr)
      conn.close()
      os._exit(0)
    else:
      conn.close()

  def handle_request(self,conn,addr):
    data = conn.recv(1024)
    print "Message From " + addr[0] + " : " + data
    print 'Connected by ', addr, 'Number of connections: ', self.num_connections
    print ">>>>>>>>>>>>>"
    if addr[0] not in self.blacklist.keys():	
      command, path, httpv= data.split()   #strip HTTP request "GET /%s HTTP/1.1\r\n" to get filename
		
    
      if path in self.h_tokens:
        self.blacklist[addr[0]] = 1
        print addr[0], "added to black list"
        print self.blacklist
      else:
      	pass
      datapath = "/home/mininet"+ path

      if self.captcha_mode == 1:
      	captcha = "I am captcha"
      	self.msg = "Enter the captcha u see"
      	conn.send(self.msg)

      else:
      	self.msg = "u are nt authorized"
      	conn.send(self.msg)
    else:
      self.blacklist[adr[0]] +=1

      command, path, httpv = data.split()

      if path in self.h_tokens:
        datapath = "/home/mininet"+path

        if self.captcha_mode == 1:
          captcha = "i am captcha"
          self.msg = "Authenticate by entering captcha"
          conn.send(self.msg)
          data = conn.recv(1024)

          if data ==self.msg:
          	fd = open(datapath)
          	self.msg = fd.read()
          	fd.close
          	conn.send(self.msg)
          else:
          	self.msg = "not autherised"
          	conn.send(self.msg)
        else:
          fd = open(datapath)
          body = fd.read()
          self.msg = "GET"+path+"HTTP/1.1\r\nDatacode 200\r\n"
          fd.close()
          conn.send(body)
      else:
      	conn.send("404 File not found")

  def handle_attack_msg(self,conn1,addr1):
    data = conn1.recv(1024)
    print "Attack Message from " + addr1[0] + ":" + data
    if "Attacked" in data:
      print "Captcha mode enabled due to attcak msg"
      self.captcha_mode = 1   
  
  def acceptattackmsg(self,x):
    print"listening from controller"
    while 1:
      conn1,addr1 = self.attack.accept()
      pid = os.fork()
      if pid == 0:
        self.attack.close()
        self.handle_attack_msg(conn1,addr1)
        conn1.close()
        os._exit(0)
      else:
        conn1.close()
            

HOST = '10.0.1.2'
PORT = 80
ADDR = (HOST,PORT)
BUFSIZE = 2048

if __name__ == '__main__':
  attackedserver = Server(HOST, PORT)
  
  #attackedserver.collectData()
  thread.start_new_thread(attackedserver.acceptattackmsg,(0,))

  while 1:
    attackedserver.acceptConnections()
