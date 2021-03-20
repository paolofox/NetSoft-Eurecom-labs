from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
import time

log = core.getLogger()
IDLE_TIMEOUT = 60 # in seconds
HARD_TIMEOUT = 0 # infinity
LOAD_BALANCER_IP = IPAddr('10.0.0.254')
LOAD_BALANCER_MAC = EthAddr('00:00:00:00:00:FE')

class LoadBalancer (EventMixin):
    
	class Server:
		def __init__ (self, ip, mac, port):
			self.ip = IPAddr(ip)
			self.mac = EthAddr(mac)
			self.port = port
		def __str__(self):
			return','.join([str(self.ip), str(self.mac), str(self.port)])
		def __init__ (self, connection):
			self.connection = connection
			self.listenTo(connection)
			# Initialize the server list
			self.servers = [
			self.Server('10.0.0.1', '00:00:00:00:00:01', 1),
			self.Server('10.0.0.2', '00:00:00:00:00:02', 2)]
			self.last_server = 0
		def get_next_server (self):
			# Round-robin load the servers
			self.last_server = (self.last_server + 1) % len(self.servers)
			return self.servers[self.last_server]
		def handle_arp (self, packet, in_port):
			# Get the ARP request from packet
			arp_req = packet.next
			# Create ARP reply
			arp_rep=arp()
			"ADD YOUR LOGIC HERE"
			# Create the Ethernet packet
			eth_rep=ethernet()
			"ADD YOUR LOGIC HERE"
			# Send the ARP reply to client. Use here the OpenFlow packet_out message
			"ADD YOUR LOGIC HERE"
		def handle_request (self, packet, event):
			# Get the next server to handle the request
			server = self.get_next_server()

			"First install the reverse rule from server to client"
			"ADD YOUR LOGIC HERE"
			# Set packet matching
			# Match (in_port, src MAC, dst MAC, src IP, dst IP)
			"ADD YOUR LOGIC HERE"
			# Append actions
			# Set the src IP and MAC to load balancer's
			# Forward the packet to client's port
			"ADD YOUR LOGIC HERE"

			"Second install the forward rule from client to server"
			"ADD YOUR LOGIC HERE"
			# Forward the incoming packet
			# Set packet matching
			# Match (in_port, MAC src, MAC dst, IP src, IP dst)
			"ADD YOUR LOGIC HERE"      # Append actions
			# Set the dst IP and MAC to load balancer's
			# Forward the packet to server's port
			"ADD YOUR LOGIC HERE"
			log.info("Installing %s <-> %s" % (packet.next.srcip, server.ip))
		def _handle_PacketIn (self, event):
			packet = event.parse()
			if packet.type == packet.LLDP_TYPE or packet.type == packet.IPV6_TYPE:
				# Drop LLDP packets
				# Drop IPv6 packets
				# send of command without actions
				msg = of.ofp_packet_out()
				msg.buffer_id = event.ofp.buffer_id
				msg.in_port = event.port
				self.connection.send(msg)
			elif packet.type == packet.ARP_TYPE:
				# Handle ARP request. You need to differentiate between ARP request for load Balancer and other ARP
				if packet.next.protodst != LOAD_BALANCER_IP:
					#Flood the ARP packet. Use the OpenFlow packet_out message
					"ADD YOUR LOGIC HERE"
					return
				log.debug("Receive an ARP request")
				self.handle_arp(packet, event.port)
			elif packet.type == packet.IP_TYPE:
				# Handle client's request
				# Only accept ARP request for load balancer
				if packet.next.dstip != LOAD_BALANCER_IP:
					return
				log.debug("Receive an IPv4 packet from %s" % packet.next.srcip)
				self.handle_request(packet, event)

class load_balancer (EventMixin):
	def __init__ (self):
		self.listenTo(core.openflow)
	def _handle_ConnectionUp (self, event):
		log.debug("Connection %s" % event.connection)
		"ADD YOUR LOGIC HERE"
		
def launch ():
	core.registerNew(load_balancer)
