import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

sr_verbose = False

known_hosts_file = 'known_hosts'

known_hosts = {}

# Parse Known hosts file
with open(known_hosts_file) as f:
    for host in f:
        mac, name = tuple([entry.strip() for entry in host.split('-')])
        known_hosts[mac] = name
