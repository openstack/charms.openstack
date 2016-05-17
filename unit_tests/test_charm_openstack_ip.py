# Note that the unit_tests/__init__.py has the following lines to stop
# side effects from the imorts from charm helpers.

# sys.path.append('./lib')
# mock out some charmhelpers libraries as they have apt install side effects
# sys.modules['charmhelpers.contrib.openstack.utils'] = mock.MagicMock()
# sys.modules['charmhelpers.contrib.network.ip'] = mock.MagicMock()

import utils

import charm.openstack.ip as ip


class TestCharmOpenStackIp(utils.BaseTestCase):

    def test_canonical_url(self):
        self.patch_object(ip, 'resolve_address', return_value='address1')
        self.patch_object(ip.net_ip, 'is_ipv6', return_value=False)
        # not ipv6
        url = ip.canonical_url()
        self.assertEqual(url, 'http://address1')
        self.resolve_address.assert_called_once_with(ip.PUBLIC)
        # is ipv6
        self.is_ipv6.return_value = True
        self.resolve_address.reset_mock()
        url = ip.canonical_url()
        self.assertEqual(url, 'http://[address1]')
        self.resolve_address.assert_called_once_with(ip.PUBLIC)
        # test we check for enpoint type
        self.is_ipv6.return_value = False
        self.resolve_address.reset_mock()
        url = ip.canonical_url(ip.INTERNAL)
        self.resolve_address.assert_called_once_with(ip.INTERNAL)

    def test_resolve_address(self):
        self.patch_object(ip.charmhelpers.contrib.hahelpers.cluster,
                          'is_clustered')
        self.patch_object(ip.hookenv, 'config')
        self.patch_object(ip.net_ip, 'is_address_in_network')
        self.patch_object(ip.net_ip, 'get_ipv6_addr')
        self.patch_object(ip.hookenv, 'unit_get')
        self.patch_object(ip.net_ip, 'get_address_in_network')

        # define a fake_config() that returns predictable results and remembers
        # what it was called with.
        calls_list = []
        _config = {
            'vip': 'vip-address',
            'prefer-ipv6': False,
            'os-public-network': 'the-public-network',
            'os-internal-network': 'the-internal-network',
            'os-admin-network': 'the-admin-network',
        }

        def fake_config(*args):
            calls_list.append(args)
            return _config[args[0]]

        self.config.side_effect = fake_config

        # first test, if not clustered, that the function uses unit_get() and
        # get_address_in_network to get a real address.
        # for the default PUBLIC endpoint
        self.is_clustered.return_value = False
        self.get_address_in_network.return_value = 'got-address'
        self.unit_get.return_value = 'unit-get-address'
        addr = ip.resolve_address()
        self.assertEqual(addr, 'got-address')
        self.assertEqual(calls_list,
                         [('prefer-ipv6',), ('os-public-network',)])
        self.unit_get.assert_called_once_with('public-address')
        self.get_address_in_network.assert_called_once_with(
            'the-public-network', 'unit-get-address')

        # second test: not clusted, prefer-ipv6 is True
        _config['prefer-ipv6'] = True
        calls_list = []
        self.get_ipv6_addr.return_value = ['ipv6-addr']
        self.get_address_in_network.reset_mock()
        addr = ip.resolve_address()
        self.get_ipv6_addr.assert_called_once_with(exc_list=['vip-address'])
        self.get_address_in_network.assert_called_once_with(
            'the-public-network', 'ipv6-addr')

        # Third test: clustered, and config(...) returns None
        self.is_clustered.return_value = True
        _config['os-public-network'] = None
        calls_list = []
        addr = ip.resolve_address()
        self.assertEqual(calls_list, [('os-public-network',), ('vip',)])

        # Fourth test: clustered, and config(...) returns not None
        _config['os-public-network'] = 'the-public-network'
        calls_list = []
        _config['vip'] = 'vip1 vip2'
        self.is_address_in_network.return_value = (False, True)
        addr = ip.resolve_address()
        self.assertEqual(calls_list, [
            ('os-public-network',),
            ('vip',),
            ('os-public-network',),
            ('os-public-network',)])
        self.assertEqual(addr, 'vip2')

        # Finally resolved_address returns None -> ValueError()
        # allow vip to not be found:
        self.is_address_in_network.return_value = False
        with self.assertRaises(ValueError):
            addr = ip.resolve_address()
