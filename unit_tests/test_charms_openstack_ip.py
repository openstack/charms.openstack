# Copyright 2016 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Note that the unit_tests/__init__.py has the following lines to stop
# side effects from the imorts from charm helpers.

# sys.path.append('./lib')
# mock out some charmhelpers libraries as they have apt install side effects
# sys.modules['charmhelpers.contrib.openstack.utils'] = mock.MagicMock()
# sys.modules['charmhelpers.contrib.network.ip'] = mock.MagicMock()

import unit_tests.utils as utils

import charms_openstack.ip as ip


class TestCharmOpenStackIp(utils.BaseTestCase):

    def test_canonical_url(self):
        self.patch_object(ip, 'resolve_address', return_value='address1')
        self.patch_object(ip.net_ip, 'is_ipv6', return_value=False)
        self.patch_object(
            ip.charms.reactive.bus, 'get_state',
            return_value=False)
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
        self.patch_object(ip.hookenv, 'config')
        self.patch_object(ip.hookenv, 'network_get_primary_address')
        self.patch_object(ip.net_ip, 'is_address_in_network')
        self.patch_object(ip.net_ip, 'get_ipv6_addr')
        self.patch_object(ip.hookenv, 'unit_get')
        self.patch_object(ip.net_ip, 'get_address_in_network')
        self.patch_object(ip.ch_os_ip, 'local_address')

        # define a fake_config() that returns predictable results and remembers
        # what it was called with.
        calls_list = []
        _config = {
            'vip': None,
            'prefer-ipv6': False,
            'os-public-network': 'the-public-network',
            'os-public-hostname': None,
            'os-internal-network': 'the-internal-network',
            'os-admin-network': 'the-admin-network',
        }

        def fake_config(*args):
            calls_list.append(args)
            return _config[args[0]]

        self.config.side_effect = fake_config

        # Juju pre 2.0 behaviour where network-get is not implemented
        self.network_get_primary_address.side_effect = NotImplementedError

        # first test, if no VIP, that the function uses local_address() and
        # get_address_in_network to get a real address.
        # for the default PUBLIC endpoint
        self.get_address_in_network.return_value = 'got-address'
        self.local_address.return_value = 'unit-get-address'
        addr = ip.resolve_address()
        self.assertEqual(addr, 'got-address')
        self.assertEqual(calls_list,
                         [('os-public-hostname',),
                          ('vip',),
                          ('os-public-network',),
                          ('prefer-ipv6',)])
        self.local_address.assert_called_once_with(
            unit_get_fallback='public-address')
        self.get_address_in_network.assert_called_once_with(
            'the-public-network', 'unit-get-address')

        # second test: no vip, prefer-ipv6 is True
        _config['prefer-ipv6'] = True
        calls_list = []
        self.get_ipv6_addr.return_value = ['ipv6-addr']
        self.get_address_in_network.reset_mock()
        addr = ip.resolve_address()
        self.get_ipv6_addr.assert_called_once_with(exc_list=None)
        self.get_address_in_network.assert_called_once_with(
            'the-public-network', 'ipv6-addr')

        # Third test: vip, and config(...) returns None
        _config['vip'] = 'vip-address'
        _config['os-public-network'] = None
        calls_list = []
        addr = ip.resolve_address()
        self.assertEqual(calls_list, [('os-public-hostname',),
                                      ('vip',),
                                      ('os-public-network',)])

        # Fourth test: clustered, and config(...) returns not None
        _config['os-public-network'] = 'the-public-network'
        calls_list = []
        _config['vip'] = 'vip1 vip2'

        def _fake_addr_in_net(address, vip):
            return True if vip == 'vip2' else False

        self.is_address_in_network.side_effect = _fake_addr_in_net
        addr = ip.resolve_address()
        self.assertEqual(calls_list, [
            ('os-public-hostname',),
            ('vip',),
            ('os-public-network',),
        ])
        self.assertEqual(addr, 'vip2')

        # Finally resolved_address returns None -> ValueError()
        # allow vip to not be found:
        self.is_address_in_network.return_value = False
        self.is_address_in_network.side_effect = None
        with self.assertRaises(ValueError):
            addr = ip.resolve_address()

    def test_resolve_address_network_binding(self):
        self.patch_object(ip.hookenv, 'config')
        self.patch_object(ip.hookenv, 'network_get_primary_address')
        self.patch_object(ip.net_ip, 'is_address_in_network')
        self.patch_object(ip.net_ip, 'get_ipv6_addr')
        self.patch_object(ip.net_ip, 'get_address_in_network')
        self.patch_object(ip, '_resolve_network_cidr')
        self.patch_object(ip.ch_os_ip, 'local_address')

        # define a fake_config() that returns predictable results and remembers
        # what it was called with.
        calls_list = []
        _config = {
            'vip': None,
            'prefer-ipv6': False,
            'os-public-network': None,
            'os-public-hostname': None,
            'os-internal-network': None,
            'os-admin-network': None,
        }

        def fake_config(*args):
            calls_list.append(args)
            return _config[args[0]]

        self.config.side_effect = fake_config

        # first test, if no vip, that the function uses unit_get
        # network_get_primary_address to get a real address.
        # for the default PUBLIC endpoint
        self.network_get_primary_address.return_value = 'got-address'
        self._resolve_network_cidr.return_value = 'cidr'
        self.local_address.return_value = 'unit-get-address'
        addr = ip.resolve_address()
        self.assertEqual(addr, 'got-address')
        self.assertEqual(calls_list,
                         [('os-public-hostname',),
                          ('vip',),
                          ('os-public-network',),
                          ('prefer-ipv6',)])
        self.local_address.assert_called_once_with(
            unit_get_fallback='public-address')
        self.network_get_primary_address.assert_called_with(
            'public'
        )

        # second test: no vip, prefer-ipv6 is True, ensure
        # that ipv6 address is fallback and network-get is still
        # used to determine the public endpoint binding
        _config['prefer-ipv6'] = True
        calls_list = []
        self.get_ipv6_addr.return_value = ['ipv6-addr']
        self.get_address_in_network.reset_mock()
        addr = ip.resolve_address()
        self.get_ipv6_addr.assert_called_once_with(exc_list=None)
        self.network_get_primary_address.assert_called_with(
            'public'
        )

        def _fake_addr_in_net(address, vip):
            return True if vip == 'vip2' else False

        self.is_address_in_network.side_effect = _fake_addr_in_net

        # Third test: clustered
        _config['vip'] = 'vip1 vip2'
        calls_list = []
        addr = ip.resolve_address()
        self.assertEqual(calls_list, [('os-public-hostname',),
                                      ('vip',),
                                      ('os-public-network',)])
        self.network_get_primary_address.assert_called_with(
            'public'
        )

        # Fourth test: clustered, and config(...) returns not None
        _config['os-public-network'] = 'the-public-network'
        calls_list = []
        _config['vip'] = 'vip1 vip2'

        addr = ip.resolve_address()
        self.assertEqual(calls_list, [
            ('os-public-hostname',),
            ('vip',),
            ('os-public-network',),
        ])
        self.assertEqual(addr, 'vip2')
        self.network_get_primary_address.assert_called_with(
            'public'
        )

#        # Finally resolved_address returns None -> ValueError()
#        # allow vip to not be found:
#        self.is_address_in_network.return_value = False
#        self.is_address_in_network.side_effect = None
#        with self.assertRaises(ValueError):
#            addr = ip.resolve_address()
