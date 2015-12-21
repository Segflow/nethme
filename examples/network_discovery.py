from nethme import *


def main():
    net = Network(iface='en0')
    print(net.gateway)
    for dev in net:  # Loop over all up hostes
        print(dev)

if __name__ == '__main__':
    main()
