from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.modules.mac_learner import mac_learner
import os
import csv
policy_file="%s/labs/lab1/firewall-policies.csv" % os.environ ['HOME']

def main():
    #intiailisation of the policies
	not_allowed = none
	
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
	
	#start with a policy that does not match any packet
	#and add traffic that is not allowed
    #for each pair two rules

	ifile = open(policy_file, "rb")
	reader = csv.reader(ifile)
	rownum = 0
	for row in reader:
		# Save header row.
		if rownum != 0:
			rule1 = match(srcmac=MAC(row[1])) & match(dstmac=MAC(row[2]))
			rule2 = match(srcmac=MAC(row[2])) & match(dstmac=MAC(row[1]))
			not_allowed = not_allowed | rule1 | rule2
		rownum += 1
	ifile.close()

	#express allowed traffic in terms of not_allowed - hint use '~'
	allowed = ~ not_allowed
	
	#and only send allowed traffic to the mac learning (act_like_switch) logic
	return allowed >> mac_learner()
