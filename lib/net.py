#!/usr/bin/env python
from netaddr import *
import re
import random


class colors:
	RD = '\033[91m'
	NRM = '\033[0m'


def IP(netaddr):
	targets = []
	IPString = netaddr
	pattern = r'[^.a-zA-Z0-9]'
	if not IPString:
		return
	elif re.search(pattern, IPString):
		if '-' in IPString:
			startIP, endIP = IPString.split('-')
			for ip in IPRange(startIP, endIP):
				targets.append(str(ip))
		elif "," in IPString:
				ips = IPString.split(',')
				for ip in ips:
					targets.append(str(ip))
		elif '/' in IPString:
			for iprange in IPNetwork(IPString):
				targets.append(str(iprange))
		else:
			print colors.RD + "[-] " + colors.NRM + "Invalid IP address"
	else:
		range = IPString.split(' ')
		for ips in range:
			targets.append(ips)
	random.shuffle(targets)
	return targets
