# DNS Monitor

dns_mon.py is a handy tool to monitor for any suspicious DNS requests initiated from home network.


# DESCRIPTION
dns_mon.py allows users to monitor their home network for any suspciious DNS activities. This tools can be
deployed on a device like RaspberryPI in between router and Access point that carries all the traffic from home
smart devices. The tool monitors for dns registration requests and validates the domains with UrlHaus for malware domains.
Upon detection of malware domain, the tool logs the warning along with reference link to UrlHaus entry.

# Why I'm Interested
After taking various courses like CSC-841, CSC-846 I found it useful to have a tool that can apply learnings including
but not limited to 1) DGA(Domain Generation Algorithms)
2) Network packet sniffing using scapy 3) Use of urlhaus for malware domain validation. 

The domain generated algorithms make use of deterministics obfuscated domains between C2 server and C2 client that keeps
changing periodically. Hence I found it useful to have a tool that can monitor the DNS fqdn requests and verify them against
UrlHaus malware domains list.

# Three Main Points
* Monitor suspcious C2 access requests from home network by virtue of monitoring DNS requests
* Ability to detect Known DGA domains
* Validate the DNS requests against URLHaus malware domain list which keeps updated by the community
  
# Pre-requisistes  

## python3 packages
To install python packages, do
`pip3 -r requirements.txt`

dns_mon.py requires following packages
* scapy
* colora
* requests

# Further Areas of Improvement
* Using GreyLog dashboard for monitoring malicious DNS requests reported by dns_mon.py
* Setup dns_mon.py along with aircrack-ng so that any device in the wireless network can
  install and monitor the DNS requests instead of having to install the device in between
  router and access point.

  
# Resources
Scapy DNS packet layers - https://scapy.readthedocs.io/en/latest/api/scapy.layers.dns.html
UrlHaus API acess - https://urlhaus-api.abuse.ch/#urlinfo
