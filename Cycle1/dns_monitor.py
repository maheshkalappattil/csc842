#!/usr/bin/env python

from scapy.all import *
from datetime import datetime
from colorama import Fore, Back, Style
import time
import datetime
import requests
import json
import sys

############# MODIFY THIS PART IF NECESSARY ###############
interface = 'en0'
filter_bpf = 'udp and port 53'
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/host/"

# filter DNS packets only
def select_DNS(pkt):
    pkt_time = pkt.sprintf('%sent.time%')
    try:
        # filter DNS request packets only
        if DNSQR in pkt and pkt.dport == 53:
            query_name = pkt.getlayer(DNSQR).qname.decode('utf-8').rstrip('.')
            print(f'DNS query: {query_name}')

            # check if the domain is present in URLHaus and if it is marked
            # as malware. 
            info = query_urlhaus(query_name)
            result = info.get('query_status')
            if result != 'ok':
                return

            # flag  if atleast one platform has identified it as malware domain
            black_lists = info.get('blacklists')
            urlhaus_reference = info.get('urlhaus_reference')
            for key, val in black_lists.items():
                if val != 'not listed':
                    #print(black_lists)
                    print(Fore.RED + f'flagged malware! reference: {urlhaus_reference}')
                    print(Style.RESET_ALL)
                    return
            return
    except Exception as e:
        print(f'Exception: {e}')

# invoke POST api to urlhaus with url as the post param.	
def query_urlhaus(host):
	try:
		r = requests.post(URLHAUS_API,  data={'host':host})
		if r.content:
			return json.loads(r.content)
	except Exception as e:
		print(f'urlhaus exception: {e}')

# ------ START SNIFFER 
sniff(iface=interface, filter=filter_bpf, store=0,  prn=select_DNS)