'''ODL Controller API integration'''
import requests
from jinja2 import Environment, FileSystemLoader
import charmhelpers.core.hookenv as hookenv
from charmhelpers.core.decorators import retry_on_exception

TEMPLATE_DIR = 'charms_openstack/sdn/templates'


class ODLInteractionFatalError(Exception):
    ''' Generic exception for failures in interaction with ODL '''
    pass


class ODLConfig(requests.Session):
    """Class used for interacting with an ODL controller"""

    def __init__(self, username, password, host, port='8181'):
        """Setup attributes for contacting ODLs http API"""
        super(ODLConfig, self).__init__()
        self.mount("http://", requests.adapters.HTTPAdapter(max_retries=5))
        self.base_url = 'http://{}:{}'.format(host, port)
        self.auth = (username, password)
        self.proxies = {}
        self.timeout = 10
        self.conf_url = self.base_url + '/restconf/config'
        self.oper_url = self.base_url + '/restconf/operational'
        self.netmap_url = self.conf_url + '/neutron-device-map:neutron_net_map'
        self.node_query_url = self.oper_url + '/opendaylight-inventory:nodes/'
        yang_mod_path = ('/opendaylight-inventory:nodes/node/'
                         'controller-config/yang-ext:mount/config:modules')
        self.node_mount_url = self.conf_url + yang_mod_path

    @retry_on_exception(5, base_delay=30,
                        exc_type=requests.exceptions.ConnectionError)
    def contact_odl(self, request_type, url, headers=None, data=None,
                    whitelist_rcs=None, retry_rcs=None):
        """Send request to ODL controller and return the response

        :param request_type: str HTTP Request Methods (GET, POST, DELETE etc)
        :param url: str URL to issue request against
        :param headers: str HTTP Header to be sent in request
        :param data: str Data to be sent in request
        :param whitelist_rcs: List List of acceptable return codes.
        :param retry_rcs: List List of return codes which should trigger a
                               retry

        :returns requests.Response: Response from request
        """
        response = self.request(request_type, url, data=data, headers=headers)
        ok_codes = [requests.codes.ok, requests.codes.no_content]
        retry_codes = [requests.codes.service_unavailable]
        if whitelist_rcs:
            ok_codes.extend(whitelist_rcs)
        if retry_rcs:
            retry_codes.extend(retry_rcs)
        if response.status_code not in ok_codes:
            if response.status_code in retry_codes:
                msg = "Recieved {} from ODL on {}".format(response.status_code,
                                                          url)
                raise requests.exceptions.ConnectionError(msg)
            else:
                msg = "Contact failed status_code={}, {}".format(
                    response.status_code, url)
                raise ODLInteractionFatalError(msg)
        return response

    def get_networks(self):
        """Query ODL for map of networks and physical hardware


        :returns dict: neutron_net_map eg:
          {
            "physicalNetwork": [
              {
                "name": "net_d12",
                "device": [
                  {
                    "device-name": "C240-M4-6",
                    "device-type": "vhostuser",
                    "interface": [
                      {
                        "interface-name": "TenGigabitEthernet6/0/0",
                        "macAddress": "84:b8:02:2a:5f:c3"
                      }
                    ]
                  }
                ]
              },
              {
                "name": "net_d11",
                "device": [
                  {
                    "device-name": "C240-M4-6",
                    "device-type": "vhostuser",
                    "interface": [
                      {
                        "interface-name": "TenGigabitEthernet7/0/0",
                        "macAddress": "84:b8:02:2a:5f:c4"
                      }
                    ]
                  }
                ]
              }
          }
        """
        hookenv.log('Querying macs registered with odl')
        # No netmap may have been registered yet, so 404 is ok
        odl_req = self.contact_odl(
            'GET', self.netmap_url, whitelist_rcs=[requests.codes.not_found])
        if not odl_req:
            hookenv.log('neutron_net_map not found in ODL')
            return {}
        odl_json = odl_req.json()
        if odl_json.get('neutron_net_map'):
            hookenv.log('neutron_net_map returned by ODL')
            return odl_json['neutron_net_map']
        else:
            hookenv.log('neutron_net_map NOT returned by ODL')
            return {}

    def delete_net_device_entry(self, net, device_name):
        """Delete device from network

        :param net: str Netork name that device should be deleted from
        :param device_name: str Name of device to be deleted from network
        """
        obj_url = self.netmap_url + \
            'physicalNetwork/{}/device/{}'.format(net, device_name)
        self.contact_odl('DELETE', obj_url)

    def get_odl_registered_nodes(self):
        """Query ODL to retieve a list of registered servers

        :return List: List of registered servers
        """
        hookenv.log('Querying nodes registered with odl')
        odl_req = self.contact_odl('GET', self.node_query_url)
        odl_json = odl_req.json()
        odl_node_ids = []
        if odl_json.get('nodes'):
            odl_nodes = odl_json['nodes'].get('node', [])
            odl_node_ids = [entry['id'] for entry in odl_nodes]
        hookenv.log(
            'Following nodes are registered: ' + ' '.join(odl_node_ids))
        return odl_node_ids

    def odl_register_node(self, device_name, ip):
        """Register server with ODL

        :param device_name: str
        :param ip: str
        """
        hookenv.log('Registering node {} ({}) with ODL'.format(
            device_name, ip))
        payload = self.render_node_xml(device_name, ip)
        headers = {'Content-Type': 'application/xml'}
        # Strictly a client should not retry on recipt of a bad_request (400)
        # but ODL return 400s while it is initialising
        self.contact_odl(
            'POST', self.node_mount_url, headers=headers, data=payload,
            retry_rcs=[requests.codes.bad_request])

    def odl_register_macs(self, device_name, network, interface, mac,
                          device_type='vhostuser'):
        """Register a device as part of a network

        :param device_name: str Name of server device that has the device
        :param interface: str Name of the device
        :param mac: str MAC address of the device
        :param device_type: str Device type
        """
        hookenv.log('Registering {} and {} on {}'.format(
            network, interface, mac))
        payload = self.render_mac_xml(device_name, network, interface, mac,
                                      device_type)
        headers = {'Content-Type': 'application/json'}
        self.contact_odl(
            'POST', self.netmap_url, headers=headers, data=payload)

    def get_macs_networks(self, mac):
        """List of networks a MAC address is registered with

        :returns str: List of Network names address is registered with
        """
        registered_networks = self.get_networks()
        nets = []
        phy_nets = registered_networks.get('physicalNetwork')
        if phy_nets:
            for network in phy_nets:
                for device in network.get('device', []):
                    for interface in device['interface']:
                        if interface['macAddress'] == mac:
                            nets.append(network['name'])
        return nets

    def is_device_registered(self, device_name):
        """Is device registered in ODL

        :returns boolean:
        """
        return device_name in self.get_odl_registered_nodes()

    def is_net_device_registered(self, net_name, device_name, interface_name,
                                 mac, device_type='vhostuser'):
        """Is device registered as part of a given network

        :param net_name,: str Name of network
        :param device_name: str Name of server device that has the device
        :param interface_name: str Name of the device
        :param mac: str MAC address of the device
        :param device_type: str Device type

        :returns boolean:
        """
        networks = self.get_networks()
        phy_nets = networks.get('physicalNetwork')
        if phy_nets:
            for net in phy_nets:
                if net_name == net['name']:
                    for dev in net.get('device', []):
                        if device_name == dev['device-name'] \
                                and dev['device-type'] == device_type:
                            for interface in dev['interface']:
                                if (interface_name ==
                                        interface['interface-name'] and
                                        mac == interface['macAddress']):
                                    return True
        return False

    def render_node_xml(self, device_name, ip, user='admin', password='admin'):
        """Return XML for rendering a node

        :param device_name: str Name of server to be registered
        :param ip: str IP on server to be registered
        :param user: str username for ODL controller to use to talk back to
                         server
        :param password: str password for ODL controller to use to talk back to
                             server

        :returns str: XML for rendering a node
        """
        env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
        template = env.get_template('odl_node_registration')
        node_xml = template.render(
            host=device_name,
            ip=ip,
            username=user,
            password=password,
        )
        return node_xml

    def render_mac_xml(self, device_name, network, interface, mac,
                       device_type='vhostuser'):
        """Register a device as part of a network

        :param device_name: str Name of server device that has the device
        :param network: str Name of the network for device to be registered
                            against
        :param interface: str Name of the device
        :param mac: str MAC address of the device
        :param device_type: str Device type
        """
        env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
        template = env.get_template('odl_mac_registration')
        mac_xml = template.render(
            host=device_name,
            network=network,
            interface=interface,
            mac=mac,
            device_type=device_type,
        )
        return mac_xml
