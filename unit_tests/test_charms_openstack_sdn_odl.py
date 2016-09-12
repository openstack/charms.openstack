import httpretty
import requests
import simplejson

import unit_tests.odl_responses as odl_responses
import charms_openstack.sdn.odl as odl
import unit_tests.utils as utils

NOT_JSON = "Im not json"


class ODLTest(utils.BaseTestCase):

    def setUp(self):
        super(ODLTest, self).setUp()
        self.odlc = odl.ODLConfig('bob', 'pword', '10.0.0.10', port='93')
        self.patch_object(odl.hookenv, 'log')

    def test_base(self):
        self.assertEqual(self.odlc.auth, ('bob', 'pword'))
        self.assertEqual(self.odlc.base_url, 'http://10.0.0.10:93')

    @httpretty.activate
    def test_contact_odl(self):
        httpretty.register_uri(httpretty.GET, "http://10.0.0.10:93/geturl",
                               body='[{"title": "Test Data"}]',
                               content_type="application/json", status=200)
        response = self.odlc.contact_odl('GET', 'http://10.0.0.10:93/geturl')
        self.assertEqual(response.json(), [{"title": "Test Data"}])

    @httpretty.activate
    def test_contact_odl_empty(self):
        url = 'http://10.0.0.10:93/puturl'
        httpretty.register_uri(httpretty.PUT, url,
                               body='', status=204)
        response = self.odlc.contact_odl('PUT', url)
        self.assertEqual(response.status_code, 204)

    @httpretty.activate
    def test_contact_odl_notfound(self):
        httpretty.register_uri(httpretty.GET, "http://10.0.0.10:93/geturl",
                               status=404)
        with self.assertRaises(odl.ODLInteractionFatalError):
            self.odlc.contact_odl('GET', 'http://10.0.0.10:93/geturl')

    @httpretty.activate
    def test_contact_odl_retry(self):
        httpretty.register_uri(httpretty.GET, "http://10.0.0.10:93/geturl",
                               status=404)
        with self.assertRaises(requests.exceptions.ConnectionError):
            self.odlc.contact_odl(
                'GET', 'http://10.0.0.10:93/geturl', retry_rcs=[404])

    @httpretty.activate
    def test_get_networks(self):
        url = self.odlc.netmap_url
        httpretty.register_uri(
            httpretty.GET, url, status=200, body=odl_responses.NEUTRON_NET_MAP)
        nets = self.odlc.get_networks()
        self.assertTrue('physicalNetwork' in nets.keys())
        self.assertEqual(len(nets['physicalNetwork']), 3)
        net_names = [net['name'] for net in nets['physicalNetwork']]
        for net in ['net_d10', 'net_d11', 'net_d12']:
            self.assertTrue(net in net_names)

    @httpretty.activate
    def test_get_networks_nonets(self):
        url = self.odlc.netmap_url
        httpretty.register_uri(httpretty.GET, url, status=200, body="{}")
        nets = self.odlc.get_networks()
        self.assertEqual(nets, {})

    @httpretty.activate
    def test_get_networks_no_neutron_map(self):
        url = self.odlc.netmap_url
        httpretty.register_uri(httpretty.GET, url, status=404)
        nets = self.odlc.get_networks()
        self.assertEqual(nets, {})

    @httpretty.activate
    def test_get_networks_notjson(self):
        url = self.odlc.netmap_url
        httpretty.register_uri(httpretty.GET, url, status=200, body=NOT_JSON)
        with self.assertRaises(simplejson.JSONDecodeError):
            self.odlc.get_networks()

    def test_delete_net_device_entry(self):
        self.patch_object(odl.ODLConfig, 'contact_odl')
        self.odlc.delete_net_device_entry('net_d10', 'mymachine')
        url = self.odlc.netmap_url + 'physicalNetwork/net_d10/device/mymachine'
        self.contact_odl.assert_called_with('DELETE', url)

    @httpretty.activate
    def test_get_odl_registered_nodes(self):
        url = self.odlc.node_query_url
        httpretty.register_uri(
            httpretty.GET, url, status=200,
            body=odl_responses.ODL_REGISTERED_NODES)
        nodes = self.odlc.get_odl_registered_nodes()
        self.assertEqual(nodes, ['C240-M4-6', 'controller-config'])

    @httpretty.activate
    def test_get_odl_registered_empty(self):
        url = self.odlc.node_query_url
        httpretty.register_uri(httpretty.GET, url, status=200, body="{}")
        nodes = self.odlc.get_odl_registered_nodes()
        self.assertEqual(nodes, [])

    @httpretty.activate
    def test_get_odl_registered_notjson(self):
        url = self.odlc.node_query_url
        httpretty.register_uri(httpretty.GET, url, status=200, body=NOT_JSON)
        with self.assertRaises(simplejson.JSONDecodeError):
            self.odlc.get_odl_registered_nodes()

    def test_odl_register_node(self):
        self.patch_object(odl.ODLConfig, 'contact_odl')
        url = self.odlc.node_mount_url
        self.odlc.odl_register_node('mymachine', '10.0.0.11')
        reg_call = self.contact_odl.call_args_list[0]
        self.assertTrue(reg_call[0], ('POST', url))

    def test_odl_register_macs(self):
        self.patch_object(odl.ODLConfig, 'contact_odl')
        url = self.odlc.conf_url
        self.odlc.odl_register_macs(
            "C240-M4-6", "net_d1", "TenGigabitEthernet6/0/0",
            "84:b8:02:2a:5f:c3")
        reg_call = self.contact_odl.call_args_list[0]
        self.assertTrue(reg_call[0], ('POST', url))

    @httpretty.activate
    def test_get_macs_networks(self):
        url = self.odlc.netmap_url
        httpretty.register_uri(
            httpretty.GET, url, status=200, body=odl_responses.NEUTRON_NET_MAP)
        nets = self.odlc.get_macs_networks('84:b8:02:2a:5f:c3')
        self.assertEqual(nets, ['net_d12', 'net_d10'])

    @httpretty.activate
    def test_get_macs_networks_nomatch(self):
        url = self.odlc.netmap_url
        httpretty.register_uri(
            httpretty.GET, url, status=200, body=odl_responses.NEUTRON_NET_MAP)
        nets = self.odlc.get_macs_networks('04:08:02:0a:0f:03')
        self.assertEqual(nets, [])

    @httpretty.activate
    def test_get_macs_networks_nonets(self):
        url = self.odlc.netmap_url
        httpretty.register_uri(httpretty.GET, url, status=200, body="{}")
        nets = self.odlc.get_macs_networks('04:08:02:0a:0f:03')
        self.assertEqual(nets, [])

    @httpretty.activate
    def test_is_device_registered(self):
        url = self.odlc.node_query_url
        httpretty.register_uri(
            httpretty.GET, url, status=200,
            body=odl_responses.ODL_REGISTERED_NODES)
        self.assertTrue(self.odlc.is_device_registered('C240-M4-6'))

    @httpretty.activate
    def test_is_device_registered_false(self):
        url = self.odlc.node_query_url
        httpretty.register_uri(
            httpretty.GET, url, status=200,
            body=odl_responses.ODL_REGISTERED_NODES)
        self.assertFalse(self.odlc.is_device_registered('B240-M4-7'))

    @httpretty.activate
    def test_is_net_device_registered(self):
        url = self.odlc.netmap_url
        httpretty.register_uri(
            httpretty.GET, url, status=200, body=odl_responses.NEUTRON_NET_MAP)
        self.assertTrue(self.odlc.is_net_device_registered(
            'net_d10', 'C240-M4-6', 'TenGigabitEthernet6/0/0',
            '84:b8:02:2a:5f:c3'))

    @httpretty.activate
    def test_is_net_device_registered_false(self):
        url = self.odlc.netmap_url
        httpretty.register_uri(
            httpretty.GET, url, status=200, body=odl_responses.NEUTRON_NET_MAP)
        self.assertFalse(self.odlc.is_net_device_registered(
            'net_d510', 'C240-M4-6', 'TenGigabitEthernet6/0/0',
            '84:b8:02:2a:5f:c3'))
