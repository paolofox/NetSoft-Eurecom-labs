from pyretic.lib.corelib import*
from pyretic.lib.std import*

ip5=IPAddr('10.0.0.5')
ip6=IPAddr('10.0.0.6')
ip7=IPAddr('10.0.0.7')

route1=((match(switch=1)>>fwd(1))+(match(switch=2)>>fwd(2))+((match(switch=3)>>fwd(3))))
route2=((match(switch=1)>>fwd(2))+(match(switch=4)>>fwd(2))+((match(switch=3)>>fwd(4))))
route3=((match(switch=3)>>fwd(1))+(match(switch=2)>>fwd(1))+((match(switch=1)>>fwd(3))))
route4=((match(switch=3)>>fwd(2))+(match(switch=4)>>fwd(1))+((match(switch=1)>>fwd(3))))

# Useful Pyretic policies
# match(f=v): filters only those packets whose header field f's value matches v
# ~A: negates a match
# A & B: logical intersection of matches A and B
# A | B: logical union of matches A and B
# fwd(a): forward packet out port a
# flood(): send all packets to all ports on a network minimum spanning tree, except for the input port
# A >> B: A's output becomes B's input
# A + B: A's output and B's output are combined
# if_(M,A,B): if packet filtered by M, then use A, otherwise use B

myroute=((match(dstip=ip6)>>route1)+(match(dstip=ip7)>>route2)+((match(dstip=ip5) & match(srcip=ip6))>>route3)+((match(dstip=ip5) & match(srcip=ip7))>>route4))
         
def main():
	return myroute
