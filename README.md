# python-ssdp
A Python module for interacting with the Simple Service Discovery Protocol (SSDP).

# Usage
The most basic usage of this module is on the command line to discover SSDP devices and services on your local network.
```
$ python SSDP.py
Server at 192.168.0.153
  Microsoft-Windows-NT/5.1 UPnP/1.0 UPnP-Device-Host/1.0
  Device 38ea00d5-1c6f-4f38-8e04-d2aae644b525
    Root Device Description at http://192.168.0.153:2869/upnphost/udhisapi.dll?content=uuid:38ea00d5-1c6f-4f38-8e04-d2aae644b525
    Device Type schemas-upnp-org MediaServer v1
    Service Types:
      microsoft.com X_MS_MediaReceiverRegistrar v1
      schemas-upnp-org ContentDirectory v1
  Device d1536bb5-153b-4bf4-bca2-9eb099985ef0
    Root Device Description at http://192.168.0.153:2869/upnphost/udhisapi.dll?content=uuid:d1536bb5-153b-4bf4-bca2-9eb099985ef0
    Device Type schemas-upnp-org MediaServer v1
    Service Types:
      schemas-upnp-org ContentDirectory v1
      microsoft.com X_MS_MediaReceiverRegistrar v1
      schemas-upnp-org ConnectionManager v1
Server at 192.168.0.159
  Linux/2.6.35 UPnP/1.0 DiXiM/3.0
  Device e94ee5fe-0a78-11e1-b06a-34F62D350D0F
    Root Device Description at http://192.168.0.159:12346/ipc/
    Device Type schemas-sharp-co-jp AquosIPC v1
    Service Type schemas-sharp-co-jp X_IPcontrol v1
  Device dbda0c3c-0a78-11e1-9713-34F62D350D0F
    Root Device Description at http://192.168.0.159:12345/mrd/
    Device Type schemas-upnp-org MediaRenderer v1
    Service Types:
      schemas-upnp-org ConnectionManager v1
      schemas-upnp-org AVTransport v1
      schemas-upnp-org RenderingControl v1
Server at 192.168.0.169
  Network Printer Server UPnP/1.0 V3.00.01.04     JUN-19-2014
  Device 16a65700-007c-1000-bb49-30cda78c6f3e
    Root Device Description at http://192.168.0.169:5200/Printer.xml
    Device Type schemas-upnp-org Printer v1
    Service Type schemas-upnp-org PrintBasic v1
Server at 192.168.0.155
  KnOS/3.2 UPnP/1.0 DMP/3.5
  Device 5f9ec1b3-ff59-19bb-8530-0005cd3519c5
    Root Device Description at http://192.168.0.155:8080/description.xml
    Device Type schemas-upnp-org MediaRenderer v1
    Service Types:
      schemas-upnp-org RenderingControl v1
      schemas-upnp-org ConnectionManager v1
      schemas-upnp-org AVTransport v1
```
View ```python SSDP.py --help``` for a complete list of options.

To use it in a script, the most common usage is calling ```search()``` to locate a device or service.
```
import SSDP
ssdp_responses = SSDP.search()
for response in ssdp_responses:
    print(response.root_device_desc_url)
```

You can search for more specific devices by passing a search target.
```
SSDP.search(search_target=SSDP.SearchTargetDeviceType('schemas-upnp-org', 'MediaRenderer', '1'))
```

If you want to execute the search function in a non-blocking mode, pass in a callbacks function to call when responses are received.
```
def my_callback_func(ssdp_message):
    print("SSDP Response Recieved: {}".format(ssdp_message))

SSDP.search(callbacks=my_callback_func)
# The search function will immediately return
```
