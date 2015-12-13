# Nethme (Network hacking made easy)

Nethme aim to make network hacking easy by providing classes such as `Network` and `Device` classes.

`Nethme` is written in `python` and uses `scapy` for packets crafting and manipulation.


## How to use

### Network object
Start by creating a `Network` object

```python
from nethme import *

net = Network(iface='en0')
```

The Network class provide many functions and attributes such as:

  - `gateway` property return a Device object describing the default gateway
  ```python
  print(net.gateway)
  ```
  - `this_device` property return a Device object of the device executing `nethme`
  ```python
  print(net.this_device)
  ```
  - Find a device using MAC or IP addresses, note that for now `nethme` only use `ARP` to find devices.
  ```python
  try:
      dev = net.get_device(ip='192.168.1.5')
  except DeviceNotFoundException as e:
      print(e)
  ```
  - Loop over all up hosts:
  ```python
  for device in net:
      print(device, "is up")
  ```
### Device object
The `Device` object represent a device in a local network can be used to perform actions such as:
  - ARP Poison: The `poison_arp` method will poison the ARP entry related to default gateway if no argument is passed.
  Note that the method will spwn a new thread and keep sending ARP `who_has` requests forever.
  ```python
  try:
      dev = net.get_device(ip='192.168.1.5')
  except DeviceNotFoundException as e:
      print(e)
  else:
      dev.poison_arp()
  ```
  - Intercept request: For now `nethme` only support the `http_request` event
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
Now `Nethme` is being developed only by me and only support basic things, the project is not very stable and may be buggy sometimes.

# TODO:
- Implement other host discovery methods
- Write installation guide
- Check open ports/services on a given device
- Comment the code
- Implement other event intercepter
- Improve the `http_request` event intercepter
- Improve this README
- Many other things..
