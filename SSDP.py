"""
This module provides convenience functions and classes for creating clients and servers supporting Simple Service
Discovery Protocol. This module follows the details in these specifications:

    Simple Service Discovery Protocol/1.0 IETF Draft v1.3. Available from
    https://tools.ietf.org/html/draft-cai-ssdp-v1-03.

    UPnP Device Architecture v1.1. Available from http://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf. More
    specifically, Section 1 (Discovery).

The most simple and popular use of this module is to discover devices

    search()

which creates a SSDPClient, sends out a SSDPMulticastSearchRequest, and returns a list of 
SSDPSearchResponse objects received. A non-blocking version is available

    search(callbacks=callback_func)

or you can look for a specific device

    search(search_target=SearchTargetDeviceType(domain_name='schemas-upnp-org', device_type='MediaRenderer', ver='1'))

The hiearchy of message classes is:

    SSDPMessage
        SSDPNotify (Server -> Client)
            SSDPNotifyAvailable
            SSDPNotifyUnavailable
            SSDPNotifyUpdate
        SSDPSearchRequest (Client -> Server)
            SSDPMulticastSearchRequest
            SSDPUnicastSearchRequest
        SSDPSearchResponse (Server -> Client)

"""
import argparse
import socket
import threading
import time


SSDP_MULTICAST_ADDR = ('239.255.255.250', 1900)
SSDP_MULTICAST_ADDR_STR = "%s:%d" % SSDP_MULTICAST_ADDR


class SSDPMessage(object):
    """
    Represents a generic SSDP message. Contains a superset of all SSDP message fields. Fields that aren't
    used are given a value of None. For more specific SSDP message types see the SSDP* objects.
    """
    ATTR_FIELD_MAP = {
        'host': 'HOST',
        'man': 'MAN',
        'max_wait_time': 'MX',
        'search_target': 'ST',
        'max_age_seconds': 'CACHE-CONTROL',
        'root_device_desc_url': 'LOCATION',
        'notification_type': 'NT',
        'notification_sub_type': 'NTS',
        'user_agent': 'USER-AGENT',
        'server': 'SERVER',
        'unique_service_name': 'USN',
        'date': 'DATE',
        'ext': 'EXT',
        'boot_id': 'BOOTID.UPNP.ORG',
        'config_id': 'CONFIGID.UPNP.ORG',
        'search_port': 'SEARCHPORT.UPNP.ORG',
    }
    REQUEST_RESPONSE_LINE = ''

    def __init__(self, host=None, man=None, max_wait_time=None, search_target=None, max_age_seconds=None,
                 root_device_desc_url=None, notification_type=None, notification_sub_type=None, user_agent=None,
                 server=None, unique_service_name=None, date=None, ext=None, boot_id=None,
                 config_id=None, search_port=None, vendor_defined_header_fields=None):
        self.host = host  # HOST Field
        self.man = man  # MAN Field
        self.max_wait_time = max_wait_time  # MX Field
        self.search_target = search_target  # ST Field
        if isinstance(self.search_target, str):
            # If the search target is a string, try to parse it
            try:
                self.search_target = create_search_target_from_str(self.search_target)
            except:
                pass
        self.max_age_seconds = max_age_seconds  # CACHE-CONTROL Field
        self.root_device_desc_url = root_device_desc_url  # LOCATION Field
        self.notification_type = notification_type  # NT Field
        self.notification_sub_type = notification_sub_type  # NTS Field
        self.user_agent = user_agent  # USER-AGENT Field
        self.server = server  # SERVER Field
        self.unique_service_name = unique_service_name  # USN Field
        if isinstance(self.unique_service_name, str):
            # If the search target is a string, try to parse it
            try:
                self.unique_service_name = create_usn_from_str(self.unique_service_name)
            except:
                pass
        self.date = date
        self.received_time = date  # Used for calculating expiration
        if self.received_time is None:
            self.received_time = time.time()
        self.ext = ext  # EXT Field
        self.boot_id = boot_id  # BOOTID.UPNP.ORG Field
        self.config_id = config_id  # CONFIGID.UPNP.ORG Field
        self.search_port = search_port  # SEARCHPORT.UPNP.ORG Field
        self.vendor_defined_header_fields = vendor_defined_header_fields
        if self.vendor_defined_header_fields is None:
            self.vendor_defined_header_fields = {}
    
    def get_header_str(self):
        """Gets a string suitable for sending out in the header portion of an HTTP request or response."""
        headers = [self.REQUEST_RESPONSE_LINE]
        for attr in self.ATTR_FIELD_MAP:
            attr_value = getattr(self, attr)
            if attr_value is not None:
                field = self.ATTR_FIELD_MAP[attr]
                if isinstance(field, tuple):
                    field = field[0]
                headers.append('%s: %s' % (field, str(attr_value)))
        # Add our Vendor-Defined Header Fields
        for vendor_field in self.vendor_defined_header_fields:
            headers.append('%s: %s' % (vendor_field.upper(), str(self.vendor_defined_header_fields)))
        headers.append('')  # According to the UPnP spec, there must be a blank line at the end
        headers.append('')
        headers.append('')
        return '\r\n'.join(headers)


class SSDPNotify(SSDPMessage):
    """
    Represents a SSDP NOTIFY message. A SSDP notify message always has "NOTIFY * HTTP/1.1" as the
    request line.
    """
    REQUEST_RESPONSE_LINE = 'NOTIFY * HTTP/1.1'

    def __init__(self, max_age_seconds=None, root_device_desc_url=None,
                 notification_type=None, notification_sub_type=None, server=None,
                 unique_service_name=None, boot_id=None, config_id=None, search_port=None,
                 vendor_defined_header_fields=None):
        SSDPMessage.__init__(
            self, host=SSDP_MULTICAST_ADDR_STR, max_age_seconds=max_age_seconds,
            root_device_desc_url=root_device_desc_url, notification_type=notification_type,
            notification_sub_type=notification_sub_type, server=server,
            unique_service_name=unique_service_name, boot_id=boot_id, config_id=config_id,
            search_port=search_port, vendor_defined_header_fields=vendor_defined_header_fields
        )


class SSDPNotifyAvailable(SSDPNotify):
    VALID_ARGS = ['max_age_seconds', 'root_device_desc_url', 'notification_type', 'server',
                  'unique_service_name', 'boot_id', 'config_id', 'search_port']

    def __init__(self, max_age_seconds, root_device_desc_url, notification_type, server,
                 unique_service_name, boot_id, config_id, search_port=None,
                 vendor_defined_header_fields=None):
        SSDPNotify.__init__(
            self, max_age_seconds=max_age_seconds, root_device_desc_url=root_device_desc_url,
            notification_type=notification_type, notification_sub_type='ssdp:alive', server=server,
            unique_service_name=unique_service_name, boot_id=boot_id, config_id=config_id,
            search_port=search_port, vendor_defined_header_fields=vendor_defined_header_fields
        )

    def is_valid(self):
        return time.time() > (self.received_time + self.max_age_seconds)


class SSDPNotifyUnavailable(SSDPNotify):
    VALID_ARGS = ['notification_type', 'unique_service_name', 'boot_id', 'config_id']

    def __init__(self, notification_type, unique_service_name, boot_id, config_id,
                 vendor_defined_header_fields=None):
        SSDPNotify.__init__(
            self, notification_type=notification_type, notification_sub_type='ssdp:byebye',
            unique_service_name=unique_service_name, boot_id=boot_id, config_id=config_id,
            vendor_defined_header_fields=vendor_defined_header_fields
        )


class SSDPNotifyUpdate(SSDPNotify):
    VALID_ARGS = ['root_device_desc_url', 'notification_type', 'unique_service_name',
                  'boot_id', 'config_id', 'search_port']

    def __init__(self, root_device_desc_url, notification_type, unique_service_name,
                 boot_id, config_id, search_port=None, vendor_defined_header_fields=None):
        super(SSDPNotifyUpdate, self).__init__(
            root_device_desc_url=root_device_desc_url, notification_type=notification_type,
            notification_sub_type='ssdp:update', unique_service_name=unique_service_name,
            boot_id=boot_id, config_id=config_id, search_port=search_port,
            vendor_defined_header_fields=vendor_defined_header_fields
        )


class SSDPSearchRequest(SSDPMessage):
    """
    Represents a SSDP M-SEARCH message. A SSDP M-SEARCH message always has "M-SEARCH * HTTP/1.1" as the
    request line.
    """
    REQUEST_RESPONSE_LINE = 'M-SEARCH * HTTP/1.1'

    def __init__(self, host=None, max_wait_time=None, search_target=None,
                 user_agent=None, vendor_defined_header_fields=None):
        super(SSDPSearchRequest, self).__init__(
            host=host, man='"ssdp:discover"', max_wait_time=max_wait_time,
            search_target=search_target, user_agent=user_agent,
            vendor_defined_header_fields=vendor_defined_header_fields
        )


class SSDPMulticastSearchRequest(SSDPSearchRequest):
    """
    Represents a SSDP M-SEARCH message using the multicast address.
    """
    VALID_ARGS = ['max_wait_time', 'search_target', 'user_agent']

    def __init__(self, max_wait_time, search_target, user_agent=None,
                 vendor_defined_header_fields=None):
        super(SSDPMulticastSearchRequest, self).__init__(
            host=SSDP_MULTICAST_ADDR_STR, max_wait_time=max_wait_time,
            search_target=search_target, user_agent=user_agent,
            vendor_defined_header_fields=vendor_defined_header_fields
        )


class SSDPUnicastSearchRequest(SSDPSearchRequest):
    """
    Represents a SSDP M-SEARCH message using a unicast address.
    """
    VALID_ARGS = ['host', 'search_target', 'user_agent']

    def __init__(self, host, search_target, user_agent=None, vendor_defined_header_fields=None):
        super(SSDPUnicastSearchRequest, self).__init__(
            host=host, search_target=search_target, user_agent=user_agent,
            vendor_defined_header_fields=vendor_defined_header_fields
        )


class SSDPSearchResponse(SSDPMessage):
    """
    Represents a SSDP M-SEARCH response message.
    """
    REQUEST_RESPONSE_LINE = 'HTTP/1.1 200 OK'
    VALID_ARGS = ['search_target', 'max_age_seconds', 'root_device_desc_url', 'server',
                  'unique_service_name', 'boot_id', 'config_id', 'search_port',
                  'received_time']

    def __init__(self, search_target, max_age_seconds, root_device_desc_url, server,
                 unique_service_name, boot_id=None, config_id=None, search_port=None,
                 date=None, vendor_defined_header_fields=None, addr=None):
        super(SSDPSearchResponse, self).__init__(
            search_target=search_target, max_age_seconds=max_age_seconds,
            root_device_desc_url=root_device_desc_url, server=server,
            unique_service_name=unique_service_name, boot_id=boot_id, config_id=config_id,
            search_port=search_port, date=date,
            vendor_defined_header_fields=vendor_defined_header_fields
        )
        self.addr = addr

    def is_valid(self):
        """Returns True/False indicating if this message was received more than max_age_seconds ago."""
        return time.time() > (self.received_time + self.max_age_seconds)

    def __repr__(self):
        return_str = "SSDPSearchResponse(search_target={}, ".format(repr(self.search_target))
        return_str += "max_age_seconds={}, ".format(self.max_age_seconds)
        return_str += "root_device_desc_url='{}', ".format(self.root_device_desc_url)
        return_str += "server='{}', ".format(self.server)
        return_str += "unique_service_name='{}'".format(self.unique_service_name)
        if self.boot_id is not None:
            return_str += ", boot_id={}".format(self.boot_id)
        if self.config_id is not None:
            return_str += ", config_id={}".format(self.config_id)
        if self.search_port is not None:
            return_str += ", search_port={}".format(self.search_port)
        if self.date is not None:
            return_str += ", date={}".format(self.date)
        if self.vendor_defined_header_fields is not None:
            return_str += ", vendor_defined_header_fields={}".format(self.vendor_defined_header_fields)
        if self.addr is not None:
            return_str += ", addr={}".format(self.addr)
        return return_str


class SearchTarget(object):
    """Represents the ST field of a SSDP message."""
    def __repr__(self):
        return "SearchTarget()"


class SearchTargetAll(SearchTarget):
    def __str__(self):
        return 'ssdp:all'

    def __repr__(self):
        return "SearchTargetAll()"


class SearchTargetRootDevice(SearchTarget):
    def __str__(self):
        return 'upnp:rootdevice'

    def __repr__(self):
        return "SearchTargetRootDevice()"


class SearchTargetDevice(SearchTarget):
    def __init__(self, uuid):
        self.uuid = uuid

    def __str__(self):
        return 'uuid:' + self.uuid

    def __repr__(self):
        return "SearchTargetDevice(uuid='{}')".format(self.uuid)


class SearchTargetDeviceType(SearchTarget):
    def __init__(self, domain_name, device_type, ver):
        self.domain_name = domain_name
        self.device_type = device_type
        self.ver = ver

    def __str__(self):
        return 'urn:%s:device:%s:%s' % (self.domain_name, self.device_type, self.ver)

    def __repr__(self):
        return "SearchTargetDeviceType(domain_name='{}', device_type='{}', ver='{}')".format(self.domain_name,
                                                                                             self.device_type, self.ver)


class SearchTargetServiceType(SearchTarget):
    def __init__(self, domain_name, service_type, ver):
        self.domain_name = domain_name
        self.service_type = service_type
        self.ver = ver

    def __str__(self):
        return 'urn:%s:service:%s:%s' % (self.domain_name, self.service_type, self.ver)

    def __repr__(self):
        return "SearchTargetServiceType(domain_name='{}', service_type='{}', ver='{}')".format(self.domain_name,
                                                                                               self.service_type,
                                                                                               self.ver)


def create_search_target_from_str(search_target_str):
    st_split = search_target_str.split(':')
    if len(st_split) < 2:
        raise Exception("All search target strings have at least one colon (:).")
    if search_target_str == 'ssdp:all':
        return SearchTargetAll()
    elif search_target_str == 'upnp:rootdevice':
        return SearchTargetRootDevice()
    elif st_split[0] == 'uuid':
        return SearchTargetDevice(st_split[1])
    elif st_split[0] == 'urn':
        if len(st_split) != 5:
            raise Exception("All Device Type and Service Type search targets have 4 colons.")
        if st_split[2] == 'device':
            return SearchTargetDeviceType(st_split[1], st_split[3], st_split[4])
        elif st_split[2] == 'service':
            return SearchTargetServiceType(st_split[1], st_split[3], st_split[4])
        else:
            raise Exception("Unknown type %s for search target %s." % (st_split[2], search_target_str))
    else:
        raise Exception("Unknown search target format " + search_target_str)


class UniqueServiceName(object):
    """Represents the USN field of a SSDP message."""
    def __init__(self, uuid):
        self.uuid = uuid

    def __str__(self):
        return "uuid:{}".format(self.uuid)


class UniqueServiceNameRootDevice(UniqueServiceName):
    def __str__(self):
        return UniqueServiceName.__str__(self) + "::upnp:rootdevice"


class UniqueServiceNameDevice(UniqueServiceName):
    def __init__(self, uuid, domain_name, device_type, ver):
        UniqueServiceName.__init__(self, uuid)
        self.domain_name = domain_name
        self.device_type = device_type
        self.ver = ver

    def __str__(self):
        return UniqueServiceName.__str__(self) + "::urn:{}:device:{}:{}".format(self.domain_name, self.device_type,
                                                                                self.ver)


class UniqueServiceNameService(UniqueServiceName):
    def __init__(self, uuid, domain_name, service_type, ver):
        UniqueServiceName.__init__(self, uuid)
        self.domain_name = domain_name
        self.service_type = service_type
        self.ver = ver

    def __str__(self):
        return UniqueServiceName.__str__(self) + "::urn:{}:service:{}:{}".format(self.domain_name, self.service_type,
                                                                                 self.ver)


def create_usn_from_str(usn_str):
    """
    Creates a UniqueServiceName object from a string.
    :param usn_str: The string to parse.
    :return: A UniqueServiceName object.
    """
    BAD_USN_EXCEPTION_STR = "Malformed USN string. Expected uuid:device-UUID[::(urn:domain-name:(service|device):" \
                            "type:ver|upnp:rootdevice)]" + " but got " + usn_str
    usn_split = usn_str.split('::')
    uuid_split = usn_split[0].split(':')
    if len(uuid_split) < 2:
        raise Exception(BAD_USN_EXCEPTION_STR)
    uuid = uuid_split[1]
    if len(usn_split) == 1:
        return UniqueServiceName(uuid)
    urn_split = usn_split[1].split(':')
    if urn_split[0] == "upnp" and urn_split[1] == "rootdevice":
        return UniqueServiceNameRootDevice(uuid)
    if len(urn_split) != 5:
        raise Exception(BAD_USN_EXCEPTION_STR)
    if urn_split[2] == "device":
        return UniqueServiceNameDevice(uuid, urn_split[1], urn_split[3], urn_split[4])
    if urn_split[2] == "service":
        return UniqueServiceNameService(uuid, urn_split[1], urn_split[3], urn_split[4])
    raise Exception(BAD_USN_EXCEPTION_STR)


def create_ssdp_message_from_header(header_str):
    """
    Creates an SSDPMessage object (or descendant) based on an HTTP header string.
    :param header_str: An HTTP header string, typically obtained from a TCP/IP socket.
    :return: A SSDPMessage object.
    """
    header_lines = header_str.split('\r\n')
    # Get our header fields
    header_fields = {}
    for line in header_lines[1:]:
        line_split = line.split(':', 1)
        if len(line_split) < 2:
            continue
        header_fields[line_split[0].upper()] = line_split[1].strip()
    message = None
    
    def get_kwarg_list(valid_args, header_fields):
        kwargs = {}
        for arg in SSDPMessage.ATTR_FIELD_MAP:
            if arg in valid_args:
                # This is a valid argument for our message type, lets see if its in the header
                if isinstance(SSDPMessage.ATTR_FIELD_MAP[arg], tuple):
                    for field in SSDPMessage.ATTR_FIELD_MAP[arg]:
                        if field in header_fields:
                            kwargs[arg] = header_fields[field]
                            break  # Only grab the first matching field
                elif SSDPMessage.ATTR_FIELD_MAP[arg] in header_fields:
                    kwargs[arg] = header_fields[SSDPMessage.ATTR_FIELD_MAP[arg]]
        # Grab all of our vendor-defined header fields
        vendor_defined_fields = {}
        for field in header_fields:
            if '.' in field:
                vendor_defined_fields[field] = header_fields[field]
        kwargs['vendor_defined_header_fields'] = vendor_defined_fields
        return kwargs

    if header_lines[0].upper() == SSDPNotify.REQUEST_RESPONSE_LINE:
        if 'NTS' not in header_fields:
            raise Exception("Required field NTS is missing from NOTIFY message. Unknown notify type.")
        if header_fields['NTS'].lower() == 'ssdp:alive':
            message = SSDPNotifyAvailable(**get_kwarg_list(SSDPNotifyAvailable.VALID_ARGS, header_fields))
        elif header_fields['NTS'].lower() == 'ssdp:byebye':
            message = SSDPNotifyUnavailable(**get_kwarg_list(SSDPNotifyUnavailable.VALID_ARGS, header_fields))
        elif header_fields['NTS'].lower() == 'ssdp:update':
            message = SSDPNotifyUpdate(**get_kwarg_list(SSDPNotifyUpdate.VALID_ARGS, header_fields))
    elif header_lines[0].upper() == SSDPSearchRequest.REQUEST_RESPONSE_LINE:
        if 'HOST' not in header_fields:
            raise Exception("Required field HOST is missing from M-SEARCH message. Unknown search type.")
        if header_fields['HOST'] == SSDP_MULTICAST_ADDR_STR:
            message = SSDPMulticastSearchRequest(**get_kwarg_list(SSDPMulticastSearchRequest.VALID_ARGS, header_fields))
        else:
            message = SSDPUnicastSearchRequest(**get_kwarg_list(SSDPUnicastSearchRequest.VALID_ARGS, header_fields))
    elif header_lines[0].upper() == SSDPSearchResponse.REQUEST_RESPONSE_LINE:
        message = SSDPSearchResponse(**get_kwarg_list(SSDPSearchResponse.VALID_ARGS, header_fields))
    else:
        raise Exception("Unknown message type " + header_lines[0])
    return message


def search(search_target=SearchTargetAll(), addr=SSDP_MULTICAST_ADDR, is_multicast=True,
           response_wait_time_seconds=3, callbacks=None):
    """
    This function is the entry point for most people using this module. Searches the network for SSDP devices and
    services.
    :param search_target: What to search for. One of the SearchTarget* objects.
    :param addr: The IP address to target.
    :param is_multicast: Indicates if our IP address is a multicast address.
    :param response_wait_time_seconds: How long to wait for responses.
    :param callbacks: Function(s) to call for each response received. If callbacks is None, this function will block for
        response_wait_time_seconds seconds.
    :return: If called in blocking mode (callbacks == None), a list of SSDPSearchResponse objects.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    if is_multicast:
        # We specify SO_REUSEADDR = 1 so multiple applications can bind to the multicast address. Its
        # not needed for unicast connections, but we go ahead and include it to simplify things.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)  # Try to remove
        search_request = SSDPMulticastSearchRequest(max_wait_time=response_wait_time_seconds-1,
                                                    search_target=search_target)
    else:
        host = addr[0] + ':' + addr[1]
        search_request = SSDPUnicastSearchRequest(host=host, search_target=search_target)
    #print(search_request.get_header_str())
    sock.sendto(search_request.get_header_str(), addr)

    def accept_responses(response_wait_time_seconds=response_wait_time_seconds, callbacks=callbacks):
        search_responses = []
        response_wait_start = time.time()
        while time.time() < response_wait_start + response_wait_time_seconds:
            socket_timeout = response_wait_start + response_wait_time_seconds - time.time()
            if socket_timeout < 0.1:
                socket_timeout = 0.1
            sock.settimeout(socket_timeout)
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                continue
            # print(data)
            search_response = create_ssdp_message_from_header(data)
            if search_response is None:
                continue
            search_response.addr = addr
            search_responses.append(search_response)
            if callbacks is not None:
                if callable(callbacks):
                    callbacks = [callbacks]
                for callback in callbacks:
                    callback(search_response)
        return search_responses

    if callbacks:
        # If callbacks were provided, lets do a non-blocking receive
        threading.Thread(
            target=accept_responses, 
            kwargs={
                'response_wait_time_seconds': response_wait_time_seconds,
                'callbacks': callbacks
            }
        ).start()
    else:
        return accept_responses(response_wait_time_seconds=response_wait_time_seconds, callbacks=callbacks)


def main(args=None):
    cmd_line_parser = argparse.ArgumentParser(
        description="A Python module for speaking Simple Server Discovery Protocol (SSDP).",
        epilog="For questions, comments, or contributions, visit this project on GitHub at "
               "http://github.com/carlsapp/ssdp/."
    )
    cmd_line_parser.add_argument('-w', '--wait-time', dest='wait_time', type=int, default=3,
                                 help="Time (in seconds) to wait for responses to a search request.")
    cmd_line_parser.add_argument('--root', action='store_true',
                                 help="Search only for root devices.")
    cmd_line_args = cmd_line_parser.parse_args(args)

    if cmd_line_args.root:
        st = SearchTargetRootDevice()
    else:
        st = SearchTargetAll()
    ssdp_search_responses = search(search_target=st, response_wait_time_seconds=cmd_line_args.wait_time)
    servers = {}
    # Organize our responses by server, UUID, and type of response
    for response in ssdp_search_responses:
        ip_addr = response.addr[0]
        if ip_addr not in servers:
            servers[ip_addr] = dict()
        if not isinstance(response.unique_service_name, UniqueServiceName):
            # We must have something that isn't SSDP mixed in here
            continue
        uuid = response.unique_service_name.uuid
        if uuid not in servers[ip_addr]:
            servers[ip_addr][uuid] = {
                'Service Types': [],
                'Device Types': [],
                'All Responses': [],
            }
        if isinstance(response.search_target, SearchTargetDeviceType):
            servers[ip_addr][uuid]['Device Types'].append(response)
        elif isinstance(response.search_target, SearchTargetServiceType):
            servers[ip_addr][uuid]['Service Types'].append(response)
        servers[ip_addr][uuid]['All Responses'].append(response)
    for server_addr in servers:
        print("Server at {}".format(server_addr))
        first_uuid = servers[server_addr].keys()[0]
        print("  {}".format(servers[server_addr][first_uuid]['All Responses'][0].server))
        for uuid in servers[server_addr]:
            dev_info = servers[server_addr][uuid]
            print("  Device {}".format(uuid))
            print("    Root Device Description at {}".format(dev_info['All Responses'][0].root_device_desc_url))
            if len(dev_info['Device Types']) != 0:
                if len(dev_info['Device Types']) == 1:
                    st = dev_info['Device Types'][0].search_target
                    print("    Device Type {} {} v{}".format(st.domain_name,
                                                             st.device_type,
                                                             st.ver))
                else:
                    print("    Device Types:")
                    for search_response in dev_info['Device Types']:
                        print("      {} {} v{}".format(search_response.search_target.domain_name,
                                                       search_response.search_target.device_type,
                                                       search_response.search_target.ver))
            if len(dev_info['Service Types']) != 0:
                if len(dev_info['Service Types']) == 1:
                    st = dev_info['Service Types'][0].search_target
                    print("    Service Type {} {} v{}".format(st.domain_name,
                                                              st.service_type,
                                                              st.ver))
                else:
                    print("    Service Types:")
                    for search_response in dev_info['Service Types']:
                        print("      {} {} v{}".format(search_response.search_target.domain_name,
                                                       search_response.search_target.service_type,
                                                       search_response.search_target.ver))


if __name__ == '__main__':
    main()
