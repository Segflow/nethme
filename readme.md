# Nethme (Network hacking made easy)

Nethme aims to make network hacking easy by providing a single, yet powerfull API such as `Network` and `Device` classes.

`Nethme` is written in `python` and uses `scapy` for packets crafting and manipulation.

## How to get started

1. clone this repo

2. install all the necessary packages (we recommend using a virtual environment)
> pip install -r requirements.txt

3. check the `examples` folder and start Hacking.

4. if you like this project, give it a star :)


## How to use

### Network object
Start by creating a `Network` object

```python
from nethme import *

net = Network(iface='en0')
```

The Network class provides many functions and attributes such as:

  * `gateway` property returns a Device object describing the default gateway
```python
print(net.gateway)
```
  * `this_device` property returns a Device object of the machine executing `nethme`
```python
print(net.this_device)
```
  * Find a device using MAC or IP addresses, note that for now `nethme` only uses `ARP` to find devices.
```python
try:
      dev = net.get_device(ip='192.168.1.5')
except DeviceNotFoundException as e:
      print(e)
```
  * Loop over all up hosts:
```python
for device in net:
      print(device, "is up")
```
### Device object
The `Device` object represents a host in the local network, and can be used to perform actions such as:
  * ARP Poison: The `poison_arp` method will poison the ARP entry related to the default gateway if no argument is passed.
  Note that`poison_arp` will spwn a new thread and keep sending `who_has` ARP  requests forever.
```python
try:
      dev = net.get_device(ip='192.168.1.5')
except DeviceNotFoundException as e:
      print(e)
else:
      dev.poison_arp()
```
  * Intercept requests: For now `nethme` only support the `http_request` event
```python
def http_handler(device, http_request):
      print("Got http request packet from:", device)
      http_request.show()
try:
      victim = net.get_device(ip='192.168.1.5')
except DeviceNotFoundException as e:
      print(e)
else:
      victim.intercept('http_request', http_handler)
```

# Status
Now `Nethme` is being developed only by me, and only support basic actions, the project is not very stable and may be buggy sometimes.

# TODO:
- Implement other host discovery methods
- Follow tcp stream
- Write installation guide
- Check open ports/services on a given device
- Comment the code
- Implement other event intercepter
- Improve the `http_request` event intercepter
- Improve this README
- Many other things..
