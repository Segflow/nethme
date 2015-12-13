from nethme import *


def main():
    net = Network(iface='en0', discovery_method='ARP')
    me = net.this_device

    print("Device IP:", me.ip)
    print("Device MAC:", me.mac)
