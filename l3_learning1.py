# Copyright 2012-2013 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A stupid L3 switch

For each switch:
1) Keep a table that maps IP addresses to MAC addresses and switch ports.
   Stock this table using information from ARP and IP packets.
2) When you see an ARP query, try to answer it using information in the table
   from step 1.  If the info in the table is old, just flood the query.
3) Flood all other ARPs.
4) When you see an IP packet, if you know the destination port (because it's
   in the table from step 1), install a flow for it.
"""
import math
from pox.core import core
import pox
log = core.getLogger()
from pprint import pprint
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.tcp import tcp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str
from pox.lib.recoco import Timer
#from socket import *
import socket
import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

import time
# include as part of the betta branch
from pox.openflow.of_json import *
import struct
#import pycap.constants, pycap.protocol, pycap.inject
ETHERTYPE_IP=0x614
# Timeout for flows
FLOW_IDLE_TIMEOUT = 200

# Timeout for ARP entries
ARP_TIMEOUT = 60 * 2

# Maximum number of packet to buffer on a switch for an unknown IP
MAX_BUFFERED_PER_IP = 5

# Maximum time to hang on to a buffer for an unknown IP in seconds
MAX_BUFFER_TIME = 5


class Entry (object):
  """
  Not strictly an ARP entry.
  We use the port to determine which port to forward traffic out of.
  We use the MAC to answer ARP replies.
  We use the timeout so that if an entry is older than ARP_TIMEOUT, we
   flood the ARP request rather than try to answer it ourselves.
  """
  def __init__ (self, port, mac):
    self.timeout = time.time() + ARP_TIMEOUT
    self.port = port
    self.mac = mac

  def __eq__ (self, other):
    if type(other) == tuple:
      return (self.port,self.mac)==other
    else:
      return (self.port,self.mac)==(other.port,other.mac)
  def __ne__ (self, other):
    return not self.__eq__(other)

  def isExpired (self):
    if self.port == of.OFPP_NONE: return False
    return time.time() > self.timeout


def dpid_to_mac (dpid):
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))


class l3_switch (EventMixin):
  def __init__ (self, fakeways = [], arp_for_unknowns = False):
    # These are "fake gateways" -- we'll answer ARPs for them with MAC
    # of the switch they're connected to.
    self.fakeways = set(fakeways)

    # If this is true and we see a packet for an unknown
    # host, we'll ARP for it.
    self.arp_for_unknowns = arp_for_unknowns

    # (dpid,IP) -> expire_time
    # We use this to keep from spamming ARPs
    self.outstanding_arps = {}

    # (dpid,IP) -> [(expire_time,buffer_id,in_port), ...]
    # These are buffers we've gotten at this datapath for this IP which
    # we can't deliver because we don't know where they go.
    self.lost_buffers = {}

    # For each switch, we map IP addresses to Entries
    self.arpTable = {}

    # This timer handles expiring stuff
    self._expire_timer = Timer(5, self._handle_expiration, recurring=True)

    self.listenTo(core)

  def _handle_expiration (self):
    # Called by a timer so that we can remove old items.
    empty = []
    for k,v in self.lost_buffers.iteritems():
      dpid,ip = k

      for item in list(v):
        expires_at,buffer_id,in_port = item
        if expires_at < time.time():
          # This packet is old.  Tell this switch to drop it.
          v.remove(item)
          po = of.ofp_packet_out(buffer_id = buffer_id, in_port = in_port)
          core.openflow.sendToDPID(dpid, po)
      if len(v) == 0: empty.append(k)

    # Remove empty buffer bins
    for k in empty:
      del self.lost_buffers[k]

  def _send_lost_buffers (self, dpid, ipaddr, macaddr, port):
    """
    We may have "lost" buffers -- packets we got but didn't know
    where to send at the time.  We may know now.  Try and see.
    """
    if (dpid,ipaddr) in self.lost_buffers:
      # Yup!
      bucket = self.lost_buffers[(dpid,ipaddr)]
      del self.lost_buffers[(dpid,ipaddr)]
      log.debug("Sending %i buffered packets to %s from %s"
                % (len(bucket),ipaddr,dpid_to_str(dpid)))
      for _,buffer_id,in_port in bucket:
        po = of.ofp_packet_out(buffer_id=buffer_id,in_port=in_port)
        po.actions.append(of.ofp_action_dl_addr.set_dst(macaddr))
        po.actions.append(of.ofp_action_output(port = port))
        core.openflow.sendToDPID(dpid, po)

  def _handle_GoingUpEvent (self, event):
    self.listenTo(core.openflow)
    log.debug("Up...")

  def _handle_PacketIn (self, event):
    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed
    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return

    if dpid not in self.arpTable:
      # New switch -- create an empty table
      self.arpTable[dpid] = {}
      for fake in self.fakeways:
        self.arpTable[dpid][IPAddr(fake)] = Entry(of.OFPP_NONE,
         dpid_to_mac(dpid))

    if packet.type == ethernet.LLDP_TYPE:
      # Ignore LLDP packets
      return

    if isinstance(packet.next, ipv4):
     # log.debug("%i %i IP %s => %s", dpid,inport,
            #    packet.next.srcip,packet.next.dstip)

      # Send any waiting packets...
      self._send_lost_buffers(dpid, packet.next.srcip, packet.src, inport)

      # Learn or update port/MAC info
      if packet.next.srcip in self.arpTable[dpid]:
        if self.arpTable[dpid][packet.next.srcip] != (inport, packet.src):
          log.info("%i %i RE-learned %s", dpid,inport,packet.next.srcip)
      else:
        log.debug("%i %i learned %s", dpid,inport,str(packet.next.srcip))
      self.arpTable[dpid][packet.next.srcip] = Entry(inport, packet.src)

      # Try to forward
      dstaddr = packet.next.dstip
      if dstaddr in self.arpTable[dpid]:
        # We have info about what port to send it out on...

        prt = self.arpTable[dpid][dstaddr].port
        mac = self.arpTable[dpid][dstaddr].mac
        if prt == inport:
          log.warning("%i %i not sending packet for %s back out of the " +
                      "input port" % (dpid, inport, str(dstaddr)))
        else:
          log.debug("%i %i installing flow for %s => %s out port %i"
                    % (dpid, inport, packet.next.srcip, dstaddr, prt))

          actions = []
          actions.append(of.ofp_action_dl_addr.set_dst(mac))
          actions.append(of.ofp_action_output(port = prt))
          match = of.ofp_match.from_packet(packet, inport)
          match.dl_src = None # Wildcard source MAC

          msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=FLOW_IDLE_TIMEOUT,
                                hard_timeout=1000,
                                buffer_id=event.ofp.buffer_id,
                                actions=actions,
                                match=of.ofp_match.from_packet(packet,
                                                               inport))
          event.connection.send(msg.pack())
      elif self.arp_for_unknowns:
        # We don't know this destination.
        # First, we track this buffer so that we can try to resend it later
        # if we learn the destination, second we ARP for the destination,
        # which should ultimately result in it responding and us learning
        # where it is

        # Add to tracked buffers
        if (dpid,dstaddr) not in self.lost_buffers:
          self.lost_buffers[(dpid,dstaddr)] = []
        bucket = self.lost_buffers[(dpid,dstaddr)]
        entry = (time.time() + MAX_BUFFER_TIME,event.ofp.buffer_id,inport)
        bucket.append(entry)
        while len(bucket) > MAX_BUFFERED_PER_IP: del bucket[0]

        # Expire things from our outstanding ARP list...
        self.outstanding_arps = {k:v for k,v in
         self.outstanding_arps.iteritems() if v > time.time()}

        # Check if we've already ARPed recently
        if (dpid,dstaddr) in self.outstanding_arps:
          # Oop, we've already done this one recently.
          return

        # And ARP...
        self.outstanding_arps[(dpid,dstaddr)] = time.time() + 4

        r = arp()
        r.hwtype = r.HW_TYPE_ETHERNET
        r.prototype = r.PROTO_TYPE_IP
        r.hwlen = 6
        r.protolen = r.protolen
        r.opcode = r.REQUEST
        r.hwdst = ETHER_BROADCAST
        r.protodst = dstaddr
        r.hwsrc = packet.src
        r.protosrc = packet.next.srcip
        e = ethernet(type=ethernet.ARP_TYPE, src=packet.src,
                     dst=ETHER_BROADCAST)
        e.set_payload(r)
        log.debug("%i %i ARPing for %s on behalf of %s" % (dpid, inport,
         str(r.protodst), str(r.protosrc)))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        msg.in_port = inport
        event.connection.send(msg)

    elif isinstance(packet.next, arp):
      a = packet.next
      log.debug("%i %i ARP %s %s => %s", dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst))

      if a.prototype == arp.PROTO_TYPE_IP:
        if a.hwtype == arp.HW_TYPE_ETHERNET:
          if a.protosrc != 0:

            # Learn or update port/MAC info
            if a.protosrc in self.arpTable[dpid]:
              if self.arpTable[dpid][a.protosrc] != (inport, packet.src):
                log.info("%i %i RE-learned %s", dpid,inport,str(a.protosrc))
            else:
              log.debug("%i %i learned %s", dpid,inport,str(a.protosrc))
            self.arpTable[dpid][a.protosrc] = Entry(inport, packet.src)

            # Send any waiting packets...
            self._send_lost_buffers(dpid, a.protosrc, packet.src, inport)

            if a.opcode == arp.REQUEST:
              # Maybe we can answer

              if a.protodst in self.arpTable[dpid]:
                # We have an answer...

                if not self.arpTable[dpid][a.protodst].isExpired():
                  # .. and it's relatively current, so we'll reply ourselves

                  r = arp()
                  r.hwtype = a.hwtype
                  r.prototype = a.prototype
                  r.hwlen = a.hwlen
                  r.protolen = a.protolen
                  r.opcode = arp.REPLY
                  r.hwdst = a.hwsrc
                  r.protodst = a.protosrc
                  r.protosrc = a.protodst
                  r.hwsrc = self.arpTable[dpid][a.protodst].mac
                  e = ethernet(type=packet.type, src=dpid_to_mac(dpid),
                               dst=a.hwsrc)
                  e.set_payload(r)
                  log.debug("%i %i answering ARP for %s" % (dpid, inport,
                   str(r.protosrc)))
                  msg = of.ofp_packet_out()
                  msg.data = e.pack()
                  msg.actions.append(of.ofp_action_output(port =
                                                          of.OFPP_IN_PORT))
                  msg.in_port = inport
                  event.connection.send(msg)
                  return

      # Didn't know how to answer or otherwise handle this ARP, so just flood it
      log.debug("%i %i flooding ARP %s %s => %s" % (dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst)))

      msg = of.ofp_packet_out(in_port = inport, data = event.ofp,
          action = of.ofp_action_output(port = of.OFPP_FLOOD))
      event.connection.send(msg)
  
class FlowStats:  
  def __init__(self):
    #self.mytime = 0
    self.ipdict = {}
    self.timemap = {}
    self.p1 = 0
    self.p2 = 0
    self.p3 = 0
    self.X1  = 0 
    self.X2 = 0
    self.X3 = 0 
    self.h = {}
    self.a1 = 0.2 
    self.a2= 0.3 
    self.a3 = 0.5 
    self.delta = 0
    self.std = 0
    self.lamda = 0
    self.ddos = 0 
    self.mytime = 0
    self.ddoscheck = 0
    self.alert_server = 0 
    self.p_list = []
    self.prevX1=0
    self.prevX2=0
    self.prevX3=0
    self.p_list.append(0)
    self.p_list.append(0)
    self.p_list.append(0)
    self.alert_flag = 0
    self.ddosstartflag =0
    self.Xt1= {}
    self.Xt2 = {}
    self.Xt3 = {}
    self.mean_entropy = 0.0
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    core.openflow.addListenerByName("FlowStatsReceived", self._handle_flowstats_received) 
    #self.sock.connect(('10.0.1.2',3000))
    #core.openflow.addListenerByName("PortStatsReceived",  _handle_portstats_received) 
    #timer set to execute every five seconds
    Timer(5, self._timer_func, recurring=True)

  def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)
  
  def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8)
        s = carry_around_add(s, w)
    return ~s & 0xffff

  #handler for timer function that sends the requests to all the
  #switches connected to the controller.
  def _timer_func (self):
    for connection in core.openflow._connections.values():
      
      print "connection is" 
      print connection
      #if openflowconnection[1]==2:
      connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
	  # connection.send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
      log.debug("Sent %i flow/port stats request(s)", len(core.openflow._connections))

	  # handler to display flow statistics received in JSON format
	  # structure of event.stats is defined by ofp_flow_stats()
	#mytime = 0 #time vale static
  def _handle_flowstats_received (self,event):
    stats = flow_stats_to_list(event.stats)
    dpidi = dpidToStr(event.connection.dpid)
    print "dpid to str gives:", dpidi
    if dpidi == "00-00-00-00-00-01":
      return
	#packeti= event.parsed
	#log.debug("packet i gotis %s",type(event))
    # if(type(event) == "pox.openflow.FlowStatsReceived"	
#    log.debug("This is FlowStatsReceived from %s: %s", dpidToStr(event.connection.dpid), stats)

	#  ipdict[(f.match.nw_dst,1,dpidi)]= [];
	# ipdict[(f.match.nw_dst,3,dpidi)]
	# Get number of bytes/packets in flows for web traffic only
    web_bytes = 0
    web_flows = 0
    web_packet = 0
    flowlist= []
	#ipdict = {}
	#global mytime
    #log.debug("my time is :%d",mytime)
	# if(mytime ==5):
	#  mytime= 0 	
	#if (dpidi== "56-6e-e7-22-4d-4f" and event.stats):
    ##if event.connection.dpid not in self.timemap:
      ##self.timemap[event.connection.dpid] = 0
    self.mytime = self.mytime + 1
    
    for f in event.stats:
      #log.debug("pratik %s", f.match.nw_dst)
      if f.match.nw_dst == IPAddr("10.0.1.2"):
        log.debug("I am in if1: %d",f.packet_count)
        self.X1 = self.X1 + f.packet_count
      if f.match.nw_dst == IPAddr("10.0.1.3"):
        #log.debug("I am in if2")
        log.debug("I am in if2: %d",f.packet_count)
        self.X2 = self.X2 + f.packet_count
      if f.match.nw_dst == IPAddr("10.0.1.4"):
        self.X3 = self.X3 + f.packet_count
        log.debug("I am in if3: %d",f.packet_count)
    print " packet cout for X1 is:",self.X1
    print " packet cout for X2 is:",self.X2
    print " packet cout for X3 is:",self.X3
    self.cal_prob(self.X1,self.X2,self.X3)
    self.cal_entropy(self.p1,self.p2,self.p3,self.mytime)
    if (self.mytime >=3):
      
      self.cal_mean_entropy(self.h,self.mytime)
      self.cal_delta(self.mytime)
      self.check_ddos(self.h, self.mytime, self.mean_entropy)
      self.alert_ddos()
    print "============================================================================="  
    self.X1 = 0
    self.X2 = 0
    self.x3 = 0
	  # log.debug("Indivisual flow stat are %s",f)
	  # pprint(f)
	  # if f.match.nw_dst == "10.0.1.2":
	  #if event.connection.dpid not in ipdict:
    """  self.ipdict[event.connection.dpid]
[(f.match.nw_dst, self.timemap[event.connection.dpid])]=f.packet_count
	    #if (f.match.nw_dst,mytime,dpidi) not in ipdict:
		#ipdict[(f.match.nw_dst,mytime,dpidi)]=f.packet_count
		#if (self.timemap[event.connection.dpid] == 1 or self.timemap[event.connection.dpid] == 2):
			#if( ipdict[(f.match.nw_dst,(mytime-2),dpidi)] not in ipdict):
			# ipdict[(f.match.nw_dst,(mytime-2),dpidi)]= 0
			# log.debug("time inside is %s",self.timemap[event.connection.dpid])      
			#  self.ipdict[(f.match.nw_dst,mytime,dpidi)] = f.packet_count #- ipdict[(f.match.nw_dst,(mytime-2),dpidi)]
				
			#mytime=mytime+1     
			#else:
			  #ipdict[(f.match.nw_dst,mytime,dpidi)]=f.packet_count
      if (self.timemap[event.connection.dpid] == 1 or self.timemap[event.connection.dpid] == 2):
        self.ipdict[event.connection.dpid][(f.match.nw_dst, self.timemap[event.connection.dpid])] = f.packet_count - self.ipdict[event.connection.dpid][(f.match.nw_dst, self.timemap[event.connection.dpid]-1)]
			#mytime=mytime+1 
    self.timemap[event.connection.dpid] = self.timemap[event.connection.dpid] + 1      
    if(self.timemap[event.connection.dpid] == 3):
      self.timemap[event.connection.dpid] = 0
	  #ipdict.clear()
      #(self.ipdict[event.connection.dpid]).clear()
	  #mytime =0      
		  #if f.match.tp_dst == 8080 or f.match.tp_src == 80:
		  #web_bytes += f.byte_count
		  #web_packet += f.packet_count
		  #web_flows += 1
	 # log.info("Web traffic from %s: %s bytes (%s packets) over %s flows", 
	 # dpidToStr(event.connection.dpid), web_bytes, web_packet, web_flows)
      for i in self.ipdict:
        log.debug("dpid = %s", dpidToStr(i.keys()))
        for j in i:
          log.debug("dst ip = %s , mytime = %s", j.keys())
		  #log.debug("ip src dict i got is : (%s,%s,%s) : pkt_count %s",i,k,j,ipdict[(i,k,j)])
	 #if(mytime ==5):
	 #mytime= 0
	 #mytime= mytime+1   
   """   
	#handler to display port statistics received in JSON format
  def _handle_portstats_received (self,event):
    stats = flow_stats_to_list(event.stats)
	  #log.debug("PortStatsReceived from %s: %s",dpidToStr(event.connection.dpid), stats)

  def cal_prob(self,x1,x2,x3):
    if(x1 != 0 or x2 != 0 or x3 != 0):
      print "i am calculating probability",x1,x2,x3
      self.p1 = float(x1)/(x1+x2+x3)
      self.p2 = float(x2)/(x1+x2+x3)
      self.p3 =float(x3)/(x1+x2+x3)
      """
      if(self.p1 == 0):
        self.p1 = 1
      if(self.p2 == 0):
        self.p2 = 1
      if(self.p3 == 0):
        self.p3 = 1
      """
      self.p_list[0]=(self.p1)
      self.p_list[1]=(self.p2)
      self.p_list[2]=(self.p3)
      print "time:",self.mytime,"the probabaility list ",self.p_list

  def cal_entropy(self,prob1,prob2,prob3,time1):
    self.h[time1] = 0
    for i in self.p_list:
      if(i):
        print "entropy prob",i 
        self.h[time1] = float(self.h[time1])+ (i*(math.log10(float(1)/i)))

    print "time:", time1, "entropy",self.h[time1] 
    """
        self.h[time1] = (prob1 * (math.log10(1/prob1))) +(prob2 * (math.log10(1/prob2))) +(prob3 * (math.log10(1/prob3)))
    """
  def cal_mean_entropy(self,h,time1):
  #  print "time: ",time1, "h value in cal_mean_ent", h
    self.mean_entropy = float(self.a1*h[time1-2]) + float(self.a2*h[time1 - 1]) + float(self.a3*h[time1])
    print "time:", time1,"mean entropy before div:", self.mean_entropy
    self.mean_entropy = float(self.mean_entropy) / math.log10(3)
    print "time:", time1,"mean entropy:", self.mean_entropy

  def check_ddos(self,h,time1,mean_ent):
    print "delta i got is ",self.delta
    print "diff i got is ",(mean_ent - h[time1])
  #  if((mean_ent - h[time1]) > 0.1):
    if((0.63 - h[time1]) > 0.4):
      print "start ddos check now"
      self.ddos = 1 + self.ddos
      self.ddosstartflag=1
      self.monitor_dst_attacked(self.mytime)
    if(self.ddosstartflag ==1):
      self.ddoscheck += 1
      if(self.ddoscheck == 6):
        self.ddoscheck = 0
        self.ddosstartflag =0

  def alert_ddos(self):
    if((self.ddoscheck >= 5) and ((self.ddos/self.ddoscheck ) >= 0.6)):
      print " i am 4/5 statemnt"
      self.alert_server = 1
      self.ddoscheck = 0
      self.ddos = 0 
      self.alert_flag =1
    
  def cal_delta(self,time1):
    self.std = math.sqrt((((self.mean_entropy - self.h[time1]) **2) + ((self.mean_entropy - self.h[time1-1]) **2) +((self.mean_entropy - self.h[time1-2]) **2))/3)
    self.lamda = 1.2
    self.delta = self.std *self.lamda
    print "time:",time1,"delta:",self.delta
  
  def sendattackmsg(self,sname):
    #sock = socket.socket(AF_INET, SOCK_STREAM)
    HOST = '0'
    print "value of sname", sname
    if sname == "Server1":
      print "entered in server1"
      HOST = '10.0.1.2'
    if sname == "Server2":
      HOST = '10.0.1.3'
    if sname == "Server3":
      HOST = '10.0.1.4'
    PORT = 3000
    ADDR = (HOST, PORT)
    print "before connect in sendattackmsg()",HOST
    self.sock.connect((HOST, PORT))
    #self.sock.send("Attacked" % sname)
    self.sock.send("Attacked")
    print "Attack msg to ", sname, " sent"
 
  """
  def sendattackmsg(self,sname):
    payload = "Attacked" + sname
    tcp_packet = tcp()
    tcp_packet.srcport = 3000
    tcp_packet.dstport = 3000
    tcp_packet.payload = payload
    tcp_packet.seq = 100
    tcp_packet.off = 5

    ipv4_packet = ipv4()
    ipv4_packet.iplen = ipv4.MIN_LEN + len(tcp_packet)
    ipv4_packet.protocol = ipv4.TCP_PROTOCOL
    ipv4_packet.dstip = IPAddr('10.0.1.2')
    ipv4_packet.srcip = IPAddr('10.0.1.10')
    ipv4_packet.set_payload(tcp_packet)
    #data = ipv4_packet.split()
    #data = map(lambda x: int(x,16), data)
    data = map(lambda x: int(x,16), ipv4_packet)
    data = struct.pack("%dB" % len(data), *data)
    ipv4_packet.csum = checksum(data)    

    eth_packet = ethernet()
    eth_packet.set_payload(ipv4_packet)
    eth_packet.dst = EthAddr('00:00:00:00:00:01')
    eth_packet.src = EthAddr('00:00:00:00:00:0a')
    eth_packet.type = ethernet.IP_TYPE
    msg = of.ofp_packet_out()
    msg.data = eth_packet.pack()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    event.connection.send(msg)
  """
  def send_captcha():
    data = 'Attack'
    ethernet = pycap.protocol.ethernet(type=pycap.constants.ethernet.ETHERTYPE_IP, source='00:03:93:44:a9:92',destination='00:50:ba:8f:c4:5f')
    packet = (ethernet, data)
    pycap.inject.inject().inject(packet)  
  
  def monitor_dst_attacked(self,time1):
    if self.alert_flag == 0:
      self.prevX1= self.X1
      self.prevX2= self.X2
      self.prevX3= self.X3
      self.Xt1[time1] = self.X1
      self.Xt2[time1] = self.X2
      self.Xt3[time1] = self.X3
    if self.alert_flag :
      print " monitor alert flag"
      self.Xt1[time1] = self.X1
      self.Xt2[time1] = self.X2
      self.Xt3[time1] = self.X3
      print "rate 1", float(self.Xt1[time1] - self.Xt1[time1-1])/5
      print "rate 2", float(self.Xt2[time1] - self.Xt2[time1-1])/5
      print "rate 3", float(self.Xt3[time1] - self.Xt3[time1-1])/5
      
      if( float(self.Xt1[time1] - self.Xt1[time1-1])/5 > 80):
        print "Server 1 attacked"
        self.sendattackmsg("Server1")      
      if( float(self.Xt2[time1] - self.Xt2[time1-1])/5 > 80):
        print "Server 2 attacked"
        self.sendattackmsg("Server2")
      if( float(self.Xt3[time1] - self.Xt3[time1-1])/5 > 80):
        print "Server 3 attacked"
        self.sendattackmsg("Server3")

def launch (fakeways="", arp_for_unknowns=None):
  fakeways = fakeways.replace(","," ").split()
  fakeways = [IPAddr(x) for x in fakeways]
  if arp_for_unknowns is None:
    arp_for_unknowns = len(fakeways) > 0
  else:
    arp_for_unknowns = str_to_bool(arp_for_unknowns)
  core.registerNew(l3_switch, fakeways, arp_for_unknowns)
  core.registerNew(FlowStats)
  # attach handsers to listners
