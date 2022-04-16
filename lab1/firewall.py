from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr
import pox.lib.packet as pkt
from collections import namedtuple
import os
import csv

log = core.getLogger()
# For flow rule entries in the OpenFlow table
policyFile = "/home/user/labs/lab1/firewall-policies.csv"

class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        log.info("Enabling Firewall Module")
        # Our firewall table
        self.firewall = {}

    def sendRule (self, src, dst, duration = 0):
        """
        Drops this packet and optionally installs a flow to continue
        dropping similar ones for a while
        """
        if not isinstance(duration, tuple):
            duration = (duration,duration)
        msg = of.ofp_flow_mod()
		match = of.ofp_match()
        match.dl_src = EthAddr(src)
        match.dl_dst = EthAddr(dst)
        msg.match = match
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.priority = 100
        self.connection.send(msg)

    # function that allows adding firewall rules into the firewall table
    def AddRule (self, src=0, dst=0, value=True):
        if (src, dst) in self.firewall:
            log.info("Rule already present drop: src %s - dst %s", src, dst)
	else:
            log.info("Adding firewall rule drop: src %s - dst %s", src, dst)
            self.firewall[(src, dst)]=value
            self.sendRule(src, dst, 10000)
	    	log.info("Adding firewall rule drop: src %s - dst %s", dst, src)
            self.firewall[(dst, src)]=value
            self.sendRule(dst, src, 10000)

    def _handle_ConnectionUp (self, event):
        self.connection = event.connection

        ifile  = open(policyFile, "rb")
        reader = csv.reader(ifile)
        rownum = 0
        for row in reader:
            # Save header row.
            if rownum == 0:
                header = row
            else:
                self.AddRule(row[1], row[2])
            rownum += 1
        ifile.close()

        log.info("Firewall rules installed on %s", dpidToStr(event.dpid))

def launch ():
    '''
    Starting the Firewall module
    '''
    core.registerNew(Firewall)
