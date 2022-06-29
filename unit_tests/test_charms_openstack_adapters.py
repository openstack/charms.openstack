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

import copy
import unittest
from unittest import mock

import charms.reactive as reactive

import charms_openstack.adapters as adapters


class TestCustomProperties(unittest.TestCase):

    def test_adapter_property(self):
        with mock.patch.object(adapters, '_custom_adapter_properties', new={}):

            @adapters.adapter_property('my-int')
            def test_func():
                pass

            self.assertTrue(adapters._custom_adapter_properties['my-int'],
                            test_func)

    def test_config_property(self):
        with mock.patch.object(adapters, '_custom_config_properties', new={}):

            @adapters.config_property
            def test_func():
                pass

            self.assertTrue(adapters._custom_config_properties['test_func'],
                            test_func)

    def test_user_config_flags(self):
        cfg = {
            'config-flags': "a = b,c=d, e= f",
        }
        cls_mock = mock.MagicMock()
        with mock.patch.object(adapters.hookenv,
                               'config',
                               new=cfg):

            conf = adapters.config_flags(cls_mock)
            self.assertEqual(conf['a'], 'b')
            self.assertEqual(conf['c'], 'd')
            self.assertEqual(conf['e'], 'f')

    def test_user_config_flags_parsing_error_1(self):
        cfg = {
            'config-flags': "a = b, c = d e= f",
        }
        cls_mock = mock.MagicMock()
        with mock.patch.object(adapters.hookenv,
                               'config',
                               new=cfg):

            with self.assertRaises(RuntimeError):
                adapters.config_flags(cls_mock)

    def test_user_config_flags_parsing_error_2(self):
        cfg = {
            'config-flags': "a = b, c  d, e= f",
        }
        cls_mock = mock.MagicMock()
        with mock.patch.object(adapters.hookenv,
                               'config',
                               new=cfg):

            with self.assertRaises(RuntimeError):
                adapters.config_flags(cls_mock)

    def test_user_config_flags_missing(self):
        cfg = {
            'other-flags': 1
        }
        cls_mock = mock.MagicMock()
        with mock.patch.object(adapters.hookenv,
                               'config',
                               new=cfg):

            conf = adapters.config_flags(cls_mock)
            self.assertEqual(conf, {})

    def test_user_config_none(self):
        cfg = None
        cls_mock = mock.MagicMock()
        with mock.patch.object(adapters.hookenv,
                               'config',
                               new=cfg):

            conf = adapters.config_flags(cls_mock)
            self.assertEqual(conf, {})


class MyRelation(object):

    auto_accessors = ['this', 'that']
    relation_name = 'my-name'
    value = 'this'

    def this(self):
        return self.value

    def that(self):
        return 'that'

    def some(self):
        return 'thing'


class MyEndpointRelation(reactive.Endpoint):

    value = 'has value in config rendering'

    def a_function(self):
        return 'value is not for config rendering'

    @property
    def a_property(self):
        return self.value


class TestOpenStackRelationAdapter(unittest.TestCase):

    def test_class(self):
        r = MyRelation()
        ad = adapters.OpenStackRelationAdapter(r, ['some'])
        self.assertEqual(ad.this, 'this')
        self.assertEqual(ad.that, 'that')
        self.assertEqual(ad.some, 'thing')
        self.assertEqual(ad.relation_name, 'my-name')
        with self.assertRaises(AttributeError):
            ad.relation_name = 'hello'
        r.value = 'changed'
        self.assertEqual(ad.this, 'changed')

    def test_class_no_relation(self):
        ad = adapters.OpenStackRelationAdapter(relation_name='cluster')
        self.assertEqual(ad.relation_name, 'cluster')

    def test_make_default_relation_adapter(self):
        # test that no properties just gets the standard one.
        self.assertEqual(
            adapters.make_default_relation_adapter('fake', None, {}),
            'fake')

        # now create a fake class with some properties to work with
        class FakeRelation(object):
            a = 4

        def b(int):
            return int.a  # e.g. in test, return the 4 for the property 'b'

        kls = adapters.make_default_relation_adapter(
            FakeRelation, 'my./?-int', {'b': b})
        self.assertEqual(kls.__name__, 'MyIntRelationAdapterModified')

        i = kls()
        self.assertIsInstance(i, FakeRelation)
        self.assertEqual(i.b, 4)

    def test_class_with_endpoint_relation(self):
        er = MyEndpointRelation('my-name')
        ad = adapters.OpenStackRelationAdapter(er)
        self.assertEqual(ad.a_property, 'has value in config rendering')
        er.value = 'can change after instantiation'
        self.assertEqual(ad.a_property, 'can change after instantiation')
        with self.assertRaises(AttributeError):
            self.assertFalse(ad.a_function)


class FakeMemcacheRelation():

    auto_accessors = ['private_address']
    relation_name = 'memcache'

    def private_address(self):
        return 'private-address'

    def memcache_hosts(self):
        return ['host1', 'host2']


class TestMemcacheRelationAdapter(unittest.TestCase):

    def test_class(self):
        fake = FakeMemcacheRelation()
        memcache = adapters.MemcacheRelationAdapter(fake)
        self.assertEqual(memcache.url, 'memcached://host1:11211?timeout=5')


class FakeRabbitMQRelation():

    auto_accessors = ['vip', 'private_address', 'password', 'ssl_port']
    relation_name = 'amqp'

    def __init__(self, vip=None, ssl=False):
        self._vip = vip
        self._ssl = ssl

    def vip(self):
        return self._vip

    def private_address(self):
        return 'private-address'

    def rabbitmq_hosts(self):
        return ['host1', 'host2']

    def vhost(self):
        return 'vhost'

    def username(self):
        return 'fakename'

    def password(self):
        return 'password'

    def ssl_port(self):
        if self._ssl:
            return '5671'
        return None


class TestRabbitMQRelationAdapter(unittest.TestCase):

    def test_class(self):
        fake = FakeRabbitMQRelation(None)
        adapters.ch_ip.format_ipv6_addr.side_effect = lambda x: x
        mq = adapters.RabbitMQRelationAdapter(fake)
        self.assertEqual(mq.vhost, 'vhost')
        self.assertEqual(mq.username, 'fakename')
        self.assertEqual(mq.host, 'private-address')
        # TODO: can't do the following 2 lines as not dynamic accessors
        # fake._vip = 'vip1'
        # self.assertEqual(mq.host, 'vip1')
        self.assertEqual(mq.hosts, 'host1,host2')
        self.assertEqual(
            mq.transport_url,
            'rabbit://fakename:password@host1:5672,'
            'fakename:password@host2:5672/vhost'
        )

    def test_class_ssl(self):
        fake = FakeRabbitMQRelation(ssl=True)
        adapters.ch_ip.format_ipv6_addr.side_effect = lambda x: x
        mq = adapters.RabbitMQRelationAdapter(fake)
        self.assertEqual(mq.vhost, 'vhost')
        self.assertEqual(mq.username, 'fakename')
        self.assertEqual(mq.host, 'private-address')
        # TODO: can't do the following 2 lines as not dynamic accessors
        # fake._vip = 'vip1'
        # self.assertEqual(mq.host, 'vip1')
        self.assertEqual(mq.hosts, 'host1,host2')
        self.assertEqual(
            mq.transport_url,
            'rabbit://fakename:password@host1:5671,'
            'fakename:password@host2:5671/vhost'
        )


class FakeAPIConfigAdapter():

    @property
    def local_address(self):
        return 'this_unit_private_addr'

    @property
    def local_unit_name(self):
        return 'this_unit-1'


class FakePeerRelation():

    auto_accessors = ['private_address']
    relation_name = 'cluster'

    def ip_map(self, address_key=None):
        if not address_key:
            address_key = 'default'
        addresses = {
            'public-address': [
                ('peer_unit-1', 'peer_unit1_public_addr'),
                ('peer_unit-2', 'peer_unit2_public_addr')],
            'internal-address': [
                ('peer_unit-1', 'peer_unit1_internal_addr'),
                ('peer_unit-2', 'peer_unit2_internal_addr')],
            'admin-address': [
                ('peer_unit-1', 'peer_unit1_admin_addr'),
                ('peer_unit-2', 'peer_unit2_admin_addr')],
            'default': [
                ('peer_unit-1', 'peer_unit1_private_addr'),
                ('peer_unit-2', 'peer_unit2_private_addr')],
        }
        return addresses[address_key]


class TestPeerHARelationAdapter(unittest.TestCase):

    def test_class(self):
        test_config = {
            'os-public-network': 'public_network',
            'os-admin-network': 'admin_network',
            'os-internal-network': 'internal_network',
        }
        test_addresses = {
            'public_network': 'this_unit_public_addr',
            'admin_network': 'this_unit_admin_addr',
            'internal_network': 'this_unit_internal_addr',
        }
        test_netmasks = {
            'this_unit_public_addr': 'public_netmask',
            'this_unit_admin_addr': 'admin_netmask',
            'this_unit_internal_addr': 'internal_netmask',
            'this_unit_private_addr': 'private_netmask',
        }
        expect_full = {
            'this_unit_admin_addr': {
                'backends': {
                    'peer_unit-1': 'peer_unit1_admin_addr',
                    'peer_unit-2': 'peer_unit2_admin_addr',
                    'this_unit-1': 'this_unit_admin_addr'},
                'network': 'this_unit_admin_addr/admin_netmask'},
            'this_unit_internal_addr': {
                'backends': {
                    'peer_unit-1': 'peer_unit1_internal_addr',
                    'peer_unit-2': 'peer_unit2_internal_addr',
                    'this_unit-1': 'this_unit_internal_addr'},
                'network': 'this_unit_internal_addr/internal_netmask'},
            'this_unit_public_addr': {
                'backends': {
                    'peer_unit-1': 'peer_unit1_public_addr',
                    'peer_unit-2': 'peer_unit2_public_addr',
                    'this_unit-1': 'this_unit_public_addr'},
                'network': 'this_unit_public_addr/public_netmask'},
            'this_unit_private_addr': {
                'backends': {
                    'peer_unit-1': 'peer_unit1_private_addr',
                    'peer_unit-2': 'peer_unit2_private_addr',
                    'this_unit-1': 'this_unit_private_addr'},
                'network': 'this_unit_private_addr/private_netmask'}}
        expect_local_ns = copy.deepcopy(expect_full)
        # Remove remote units from map of local unit and networks
        for net in expect_full.keys():
            for unit in expect_full[net]['backends'].keys():
                if 'peer' in unit:
                    del expect_local_ns[net]['backends'][unit]
        expect_local_default = {
            'this_unit_private_addr': expect_local_ns['this_unit_private_addr']
        }
        del expect_local_ns['this_unit_private_addr']
        # Tests PeerHARelationAdapter with peers
        with mock.patch.object(adapters.ch_ip, 'get_relation_ip',
                               new=lambda _, x: test_addresses.get(x)), \
                mock.patch.object(adapters.ch_ip, 'get_netmask_for_address',
                                  new=lambda x: test_netmasks.get(x)), \
                mock.patch.object(adapters, 'APIConfigurationAdapter',
                                  side_effect=FakeAPIConfigAdapter), \
                mock.patch.object(adapters.hookenv, 'config',
                                  new=lambda: test_config):
            fake = FakePeerRelation()
            padapt = adapters.PeerHARelationAdapter

            peer_ra = padapt(fake)

            self.assertEqual(peer_ra.cluster_hosts, expect_full)
            lnetsplit = padapt().local_network_split_addresses()
            self.assertEqual(lnetsplit, expect_local_ns)
            ldefault = padapt().local_default_addresses()
            self.assertEqual(ldefault, expect_local_default)
            self.assertEqual(peer_ra.internal_addresses, [
                'peer_unit1_internal_addr',
                'peer_unit2_internal_addr',
                'this_unit_internal_addr'])

        # Tests PeerHARelationAdapter without peers
        with mock.patch.object(adapters.ch_ip, 'get_relation_ip',
                               new=lambda _, x: test_addresses.get(x)), \
                mock.patch.object(adapters.ch_ip, 'get_netmask_for_address',
                                  new=lambda x: test_netmasks.get(x)), \
                mock.patch.object(adapters, 'APIConfigurationAdapter',
                                  side_effect=FakeAPIConfigAdapter), \
                mock.patch.object(adapters.hookenv, 'config',
                                  new=lambda: test_config):

            # Test single_mode_map when a cluster relation is present
            with mock.patch.object(adapters.hookenv, 'relation_ids',
                                   new=lambda x: ['rid1']), \
                    mock.patch.object(adapters.hookenv, 'related_units',
                                      new=lambda relid: []):
                expect = {
                    'internal_addresses': ['this_unit_internal_addr'],
                    'cluster_hosts': expect_local_ns}
                expect['cluster_hosts']['this_unit_private_addr'] = \
                    expect_local_default['this_unit_private_addr']
                peer_ra = adapters.PeerHARelationAdapter(
                    relation_name='cluster')
                self.assertEqual(peer_ra.single_mode_map, expect)

            # Test single_mode_map when a cluster relation is not present
            # i.e is not defined in metadata.yaml
            with mock.patch.object(adapters.hookenv, 'relation_ids',
                                   new=lambda x: []):
                peer_ra = adapters.PeerHARelationAdapter(FakePeerRelation())
                self.assertEqual(peer_ra.single_mode_map, {})


class FakeDatabaseRelation():

    auto_accessors = []
    relation_name = 'shared_db'

    def db_host(self):
        return 'host1'

    def db_port(self):
        return 3306

    def username(self, prefix=''):
        return 'username1{}'.format(prefix)

    def password(self, prefix=''):
        return 'password1{}'.format(prefix)

    def database(self, prefix=''):
        return 'database1{}'.format(prefix)

    def ssl_ca(self):
        return None

    def ssl_cert(self):
        return None

    def ssl_key(self):
        return None


class FakeCharmInstance():

    def __init__(self):
        self.group = "group"
        self.options = mock.MagicMock()
        self.options.openstack_origin = "cloud:bionic-rocky"


class SSLDatabaseRelationAdapter(adapters.DatabaseRelationAdapter):

    def __init__(self, relation, ssl_dir=None, charm_instance=None):
        relation.ssl_ca = lambda: (
            adapters.base64.b64encode('my-ca'.encode('UTF-8')))
        relation.ssl_cert = lambda: (
            adapters.base64.b64encode('my-cert'.encode('UTF-8')))
        relation.ssl_key = lambda: (
            adapters.base64.b64encode('my-key'.encode('UTF-8')))
        if ssl_dir:
            super().__init__(
                relation, ssl_dir=ssl_dir, charm_instance=charm_instance)
        else:
            super().__init__(relation, charm_instance=charm_instance)


class TestDatabaseRelationAdapter(unittest.TestCase):

    def test_class(self):
        with mock.patch.object(adapters.ch_utils,
                               'get_os_codename_install_source',
                               return_value='rocky'):
            fake = FakeDatabaseRelation()
            db = adapters.DatabaseRelationAdapter(
                fake, charm_instance=FakeCharmInstance())
            self.assertEqual(db.host, 'host1')
            self.assertEqual(db.port, 3306)
            self.assertEqual(db.type, 'mysql')
            self.assertEqual(db.password, 'password1')
            self.assertEqual(db.username, 'username1')
            self.assertEqual(db.database, 'database1')
            self.assertEqual(
                db.uri,
                'mysql://username1:password1@host1:3306/database1')
            self.assertEqual(
                db.get_uri('x'),
                'mysql://username1x:password1x@host1:3306/database1x')
            self.assertEqual(
                db.get_password('x'),
                'password1x')
            # test the ssl feature of the base class
            db = SSLDatabaseRelationAdapter(
                fake, charm_instance=FakeCharmInstance())
            self.assertEqual(
                db.uri,
                'mysql://username1:password1@host1:3306/database1'
                '?ssl_ca=/usr/local/share/ca-certificates/db-client.ca'
                '&ssl_cert=/usr/local/share/ca-certificates/db-client.cert'
                '&ssl_key=/usr/local/share/ca-certificates/db-client.key')
        with mock.patch.object(adapters.ch_utils,
                               'get_os_codename_install_source',
                               return_value='stein'):
            ssl_dir = '/ssl/path'
            fake = FakeDatabaseRelation()
            db = adapters.DatabaseRelationAdapter(
                fake, charm_instance=FakeCharmInstance())
            self.assertEqual(
                db.uri,
                'mysql+pymysql://username1:password1@host1:3306/database1')
            self.assertEqual(
                db.get_uri('x'),
                'mysql+pymysql://username1x:password1x@host1:3306/database1x')
            self.assertEqual(
                db.get_password('x'),
                'password1x')
            # test the ssl feature of the base class
            db = SSLDatabaseRelationAdapter(
                fake, ssl_dir=ssl_dir, charm_instance=FakeCharmInstance())
            self.assertEqual(
                db.uri,
                'mysql+pymysql://username1:password1@host1:3306/database1'
                '?ssl_ca={ssl_dir}/db-client.ca'
                '&ssl_cert={ssl_dir}/db-client.cert'
                '&ssl_key={ssl_dir}/db-client.key'.format(ssl_dir=ssl_dir))


class TestConfigurationAdapter(unittest.TestCase):

    def test_class(self):
        test_config = {
            'one': 1,
            'two': 2,
            'three': 3,
            'that-one': 4
        }
        with mock.patch.object(adapters.hookenv, 'config',
                               new=lambda: test_config):
            c = adapters.ConfigurationAdapter()
            self.assertEqual(c.one, 1)
            self.assertEqual(c.three, 3)
            self.assertEqual(c.that_one, 4)

    def test_make_default_configuration_adapter_class(self):
        # test that emply class just gives us a normal ConfigurationAdapter
        self.assertEqual(
            adapters.make_default_configuration_adapter_class(None, {}),
            adapters.ConfigurationAdapter)
        # now test with a custom class, but no properties
        self.assertEqual(
            adapters.make_default_configuration_adapter_class(
                adapters.APIConfigurationAdapter, {}),
            adapters.APIConfigurationAdapter)
        # finally give it a custom property

        def custom_property(config):
            return 'custom-thing'

        kls = adapters.make_default_configuration_adapter_class(
            None, {'custom_property': custom_property})
        self.assertEqual(kls.__name__, 'DefaultConfigurationAdapter')
        self.assertTrue(
            'ConfigurationAdapter' in [c.__name__ for c in kls.mro()])
        # instantiate the kls and check for the property
        test_config = {
            'my-value': True,
        }
        with mock.patch.object(adapters.hookenv,
                               'config',
                               new=lambda: test_config):
            c = kls()
            self.assertTrue(c.my_value)
            self.assertEqual(c.custom_property, 'custom-thing')

    def test_charm_instance(self):
        with mock.patch.object(adapters.hookenv, 'config', new=lambda: {}):
            c = adapters.ConfigurationAdapter()
            self.assertEqual(c.charm_instance, None)

            class MockCharm(object):
                pass

            instance = MockCharm()
            c = adapters.ConfigurationAdapter(charm_instance=instance)
            self.assertEqual(c.charm_instance, instance)
            self.assertTrue(c._charm_instance_weakref is not None)

    def test_application_name(self):
        with mock.patch.object(adapters.hookenv, 'config', new=lambda: {}):
            with mock.patch.object(adapters.hookenv, 'service_name',
                                   return_value='myapp'):
                c = adapters.ConfigurationAdapter()
                self.assertEqual(c.application_name, 'myapp')


class TestAPIConfigurationAdapter(unittest.TestCase):
    api_ports = {
        'svc1': {
            'admin': 9001,
            'public': 9001,
            'internal': 9001,
        },
        'svc2': {
            'admin': 9002,
            'public': 9003,
            'internal': 9002,
        }}

    def test_class(self):
        test_config = {
            'prefer-ipv6': False,
            'vip': '',
        }
        with mock.patch.object(adapters.hookenv, 'config',
                               new=lambda: test_config), \
                mock.patch.object(adapters.APIConfigurationAdapter,
                                  'get_network_addresses'), \
                mock.patch.object(adapters.hookenv, 'local_unit',
                                  return_value='my-unit/0'):
            c = adapters.APIConfigurationAdapter()
            self.assertEqual(c.local_unit_name, 'my-unit-0')
            self.assertEqual(c.haproxy_stat_port, '8888')
            self.assertEqual(c.service_ports, {})
            self.assertEqual(c.service_listen_info, {})
            self.assertEqual(c.external_endpoints, {})

    def test_class_init_using_charm_instance(self):

        class TestCharm(object):

            active_api_ports = TestAPIConfigurationAdapter.api_ports
            name = 'test-charm'

        with mock.patch.object(adapters.hookenv, 'config', new=lambda: {}), \
                mock.patch.object(adapters.APIConfigurationAdapter,
                                  'get_network_addresses'):
            c = adapters.APIConfigurationAdapter(charm_instance=TestCharm())
            self.assertEqual(c.port_map, TestCharm.active_api_ports)
            self.assertEqual(c.service_name, 'test-charm')

    def test_ipv4_mode(self):
        test_config = {
            'prefer-ipv6': False,
            'vip': '',
        }
        with mock.patch.object(adapters.ch_utils, 'get_host_ip',
                               return_value='10.0.0.10'), \
                mock.patch.object(adapters.hookenv, 'config',
                                  new=lambda: test_config), \
                mock.patch.object(adapters.ch_os_ip, 'local_address',
                                  return_value='10.0.0.20'), \
                mock.patch.object(adapters.APIConfigurationAdapter,
                                  'get_network_addresses'):
            c = adapters.APIConfigurationAdapter(service_name='svc1')
            self.assertFalse(c.ipv6_mode)
            self.assertEqual(c.local_address, '10.0.0.10')
            self.assertEqual(c.local_host, '127.0.0.1')
            self.assertEqual(c.haproxy_host, '0.0.0.0')
            self.assertEqual(c.service_name, 'svc1')

    def test_external_endpoints(self):
        with mock.patch.object(adapters.os_ip, 'resolve_address',
                               return_value="10.0.0.10"):
            c = adapters.APIConfigurationAdapter(port_map=self.api_ports)
            self.assertEqual(
                c.external_endpoints, {
                    'svc1': {
                        'proto': 'https',
                        'ip': '10.0.0.10',
                        'port': 9001,
                        'url': 'https://10.0.0.10:9001'},
                    'svc2': {
                        'proto': 'https',
                        'ip': '10.0.0.10',
                        'port': 9002,
                        'url': 'https://10.0.0.10:9002'}})

    def test_ipv6_mode(self):
        test_config = {
            'prefer-ipv6': True,
            'vip': '',
        }
        with mock.patch.object(adapters.hookenv, 'config',
                               new=lambda: test_config), \
                mock.patch.object(
                    adapters.ch_ip,
                    'get_ipv6_addr',
                    return_value=['fe80::f2de:f1ff:fedd:8dc7']), \
                mock.patch.object(adapters.APIConfigurationAdapter,
                                  'get_network_addresses'):
            c = adapters.APIConfigurationAdapter()
            self.assertTrue(c.ipv6_mode)
            self.assertEqual(c.local_address, 'fe80::f2de:f1ff:fedd:8dc7')
            self.assertEqual(c.local_host, 'ip6-localhost')
            self.assertEqual(c.haproxy_host, '::')

    def test_ipv6_enabled(self):
        with mock.patch.object(adapters.ch_ip,
                               'is_ipv6_disabled') as is_ipv6_disabled:

            # IPv6 disabled
            is_ipv6_disabled.return_value = True
            a = adapters.APIConfigurationAdapter()
            self.assertEqual(a.ipv6_enabled, False)

            # IPv6 enabled
            is_ipv6_disabled.return_value = False
            b = adapters.APIConfigurationAdapter()
            self.assertEqual(b.ipv6_enabled, True)

    def test_external_ports(self):
        c = adapters.APIConfigurationAdapter(port_map=self.api_ports)
        self.assertEqual(c.external_ports, {9001, 9002, 9003})

    def test_get_network_addresses(self):
        test_config = {
            'prefer-ipv6': False,
            'os-admin-network': 'admin_net',
            'os-public-network': 'public_net',
            'os-internal-network': 'internal_net',
        }
        test_networks = {
            'admin_net': 'admin_addr',
            'public_net': 'public_addr',
            'internal_net': 'internal_addr',
        }
        resolved_addresses = {
            'admin': 'admin_addr',
            'public': 'public_addr',
            'int': 'int_vip',
        }

        def _is_address_in_network(cidr, vip):
            return cidr == vip.replace('vip_', '')

        def _resolve_address(endpoint_type=None):
            return resolved_addresses[endpoint_type]

        with mock.patch.object(adapters.hookenv, 'config',
                               return_value=test_config), \
                mock.patch.object(adapters.hookenv, 'unit_get',
                                  return_value='thisunit'), \
                mock.patch.object(adapters.ch_ip, 'get_address_in_network',
                                  new=lambda x, y: test_networks[x]), \
                mock.patch.object(adapters.ch_ip, 'get_relation_ip',
                                  new=lambda x, y: test_networks[x]), \
                mock.patch.object(adapters.os_ip, 'resolve_address',
                                  new=_resolve_address):
            c = adapters.APIConfigurationAdapter()
            self.assertEqual(
                c.get_network_addresses(), [
                    ('admin_addr', 'admin_addr'),
                    ('internal_addr', 'int_vip'),
                    ('public_addr', 'public_addr')])

    def test_port_maps(self):
        class MockAddrAPIConfigurationAdapt(adapters.APIConfigurationAdapter):
            @property
            def local_address(self):
                return '10.0.0.10'

        def _determine_apache_port(port, singlenode_mode=None):
            return port - 10

        with mock.patch.object(adapters.ch_cluster, 'determine_apache_port',
                               side_effect=_determine_apache_port), \
                mock.patch.object(adapters.APIConfigurationAdapter,
                                  'determine_service_port',
                                  side_effect=_determine_apache_port), \
                mock.patch.object(adapters.os_ip, 'resolve_address',
                                  return_value="10.10.10.10"):
            with mock.patch.object(adapters.APIConfigurationAdapter,
                                   'apache_enabled',
                                   new=False):
                c = MockAddrAPIConfigurationAdapt(port_map=self.api_ports)
                self.assertEqual(
                    c.service_ports,
                    {'svc1_admin': [9001, 8991],
                     'svc2_admin': [9002, 8992],
                     'svc2_public': [9003, 8993]})
                self.assertEqual(
                    c.service_listen_info, {
                        'svc1': {
                            'public_port': 8991,
                            'admin_port': 8991,
                            'internal_port': 8991,
                            'proto': 'http',
                            'ip': '10.0.0.10',
                            'port': 8991,
                            'url': 'http://10.0.0.10:8991'},
                        'svc2': {
                            'public_port': 8993,
                            'admin_port': 8992,
                            'internal_port': 8992,
                            'proto': 'http',
                            'ip': '10.0.0.10',
                            'port': 8992,
                            'url': 'http://10.0.0.10:8992'}})
                self.assertEqual(
                    c.external_endpoints, {
                        'svc1': {
                            'proto': 'http',
                            'ip': '10.10.10.10',
                            'port': 9001,
                            'url': 'http://10.10.10.10:9001'},
                        'svc2': {
                            'proto': 'http',
                            'ip': '10.10.10.10',
                            'port': 9002,
                            'url': 'http://10.10.10.10:9002'}})
            with mock.patch.object(adapters.APIConfigurationAdapter,
                                   'apache_enabled',
                                   new=True):
                c = MockAddrAPIConfigurationAdapt(port_map=self.api_ports)
                self.assertEqual(
                    c.service_ports,
                    {'svc1_admin': [9001, 8991],
                     'svc2_admin': [9002, 8992],
                     'svc2_public': [9003, 8993]})
                self.assertEqual(
                    c.service_listen_info, {
                        'svc1': {
                            'public_port': 8991,
                            'admin_port': 8991,
                            'internal_port': 8991,
                            'proto': 'http',
                            'ip': '127.0.0.1',
                            'port': 8991,
                            'url': 'http://127.0.0.1:8991'},
                        'svc2': {
                            'public_port': 8993,
                            'admin_port': 8992,
                            'internal_port': 8992,
                            'proto': 'http',
                            'ip': '127.0.0.1',
                            'port': 8992,
                            'url': 'http://127.0.0.1:8992'}})
                self.assertEqual(
                    c.external_endpoints, {
                        'svc1': {
                            'proto': 'https',
                            'ip': '10.10.10.10',
                            'port': 9001,
                            'url': 'https://10.10.10.10:9001'},
                        'svc2': {
                            'proto': 'https',
                            'ip': '10.10.10.10',
                            'port': 9002,
                            'url': 'https://10.10.10.10:9002'}})

    def test_endpoints_and_ext_ports(self):
        _net_addrs = [
            ('admin_addr', 'vip_admin_net'),
            ('internal_addr', 'vip_internal_net')]
        with mock.patch.object(adapters.APIConfigurationAdapter,
                               'get_network_addresses',
                               return_value=_net_addrs), \
                mock.patch.object(adapters.ch_cluster, 'determine_apache_port',
                                  new=lambda x, singlenode_mode: x - 10), \
                mock.patch.object(adapters.ch_cluster, 'determine_api_port',
                                  new=lambda x, singlenode_mode: x - 20):
            c = adapters.APIConfigurationAdapter(port_map=self.api_ports)
            expect = [
                ('admin_addr', 'vip_admin_net', 8991, 8981),
                ('admin_addr', 'vip_admin_net', 8992, 8982),
                ('admin_addr', 'vip_admin_net', 8993, 8983),
                ('internal_addr', 'vip_internal_net', 8991, 8981),
                ('internal_addr', 'vip_internal_net', 8992, 8982),
                ('internal_addr', 'vip_internal_net', 8993, 8983),
            ]

            self.assertEqual(c.endpoints, expect)
            self.assertEqual(c.ext_ports, [8991, 8992, 8993])

    def test_apache_enabled(self):
        with mock.patch.object(adapters.charms.reactive.bus,
                               'get_state',
                               return_value=True):
            c = adapters.APIConfigurationAdapter()
            self.assertTrue(c.apache_enabled)
        with mock.patch.object(adapters.charms.reactive.bus,
                               'get_state',
                               return_value=False):
            c = adapters.APIConfigurationAdapter()
            self.assertFalse(c.apache_enabled)

    def test_determine_service_port(self):
        with mock.patch.object(adapters.APIConfigurationAdapter,
                               'apache_enabled',
                               new=True):
            c = adapters.APIConfigurationAdapter()
            self.assertEqual(c.determine_service_port(80), 60)
        with mock.patch.object(adapters.APIConfigurationAdapter,
                               'apache_enabled',
                               new=False):
            c = adapters.APIConfigurationAdapter()
            self.assertEqual(c.determine_service_port(80), 70)

    def test_memcache_ctx(self):

        class MockCharmInstance(object):
            active_api_ports = {}
            name = 'hello'

            def __init__(self, release):
                self.release = release

        mch_result = False

        class MCHR(object):
            class_thing = None

            def __init__(self, thing):
                self.thing = thing
                self.__class__.class_thing = self

            def __gt__(self, other):
                return mch_result

        mpo = mock.patch.object
        with mpo(adapters.ch_host, 'lsb_release') as lsb_r, \
                mpo(adapters.ch_host, 'CompareHostReleases', new=MCHR), \
                mpo(adapters.ch_ip, 'is_ipv6_disabled') as is_ipv6_disabled:

            # first no memcache
            mci = MockCharmInstance('liberty')
            c = adapters.APIConfigurationAdapter(charm_instance=mci)
            self.assertEqual(c.memcache['use_memcache'], False)

            # next switch on memcache
            mci = MockCharmInstance('mitaka')
            # start with ipv6 disabled and ubuntu release is trusty
            lsb_r.return_value = {'DISTRIB_CODENAME': 'trusty'}
            is_ipv6_disabled.return_value = True
            c = adapters.APIConfigurationAdapter(charm_instance=mci)
            self.assertEqual(c.memcache['use_memcache'], True)
            self.assertEqual(MCHR.class_thing.thing, 'trusty')
            self.assertEqual(c.memcache['memcache_server'], 'localhost')
            self.assertEqual(c.memcache['memcache_server_formatted'],
                             '127.0.0.1')
            self.assertEqual(c.memcache['memcache_port'], '11211')
            self.assertEqual(c.memcache['memcache_url'],
                             '127.0.0.1:11211')
            # make us later than trusty
            mch_result = True
            self.assertEqual(c.memcache['memcache_server'], '127.0.0.1')

            # now do ipv6 not disabled.
            mch_result = False
            is_ipv6_disabled.return_value = False
            c = adapters.APIConfigurationAdapter(charm_instance=mci)
            self.assertEqual(c.memcache['use_memcache'], True)
            self.assertEqual(MCHR.class_thing.thing, 'trusty')
            self.assertEqual(c.memcache['memcache_server'], 'ip6-localhost')
            self.assertEqual(c.memcache['memcache_server_formatted'], '[::1]')
            self.assertEqual(c.memcache['memcache_port'], '11211')
            self.assertEqual(c.memcache['memcache_url'], 'inet6:[::1]:11211')
            # make us later than trusty
            mch_result = True
            self.assertEqual(c.memcache['memcache_server'], '::1')

    def test_use_memcache(self):
        with mock.patch.object(adapters.APIConfigurationAdapter, 'memcache',
                               new_callable=mock.PropertyMock) as memcache:
            memcache.return_value = {}
            c = adapters.APIConfigurationAdapter()
            self.assertEqual(c.use_memcache, False)
            memcache.return_value = {'use_memcache': False}
            self.assertEqual(c.use_memcache, False)
            memcache.return_value = {'use_memcache': True}
            self.assertEqual(c.use_memcache, True)

    def test_memcache_server(self):
        with mock.patch.object(adapters.APIConfigurationAdapter, 'memcache',
                               new_callable=mock.PropertyMock) as memcache:
            memcache.return_value = {}
            c = adapters.APIConfigurationAdapter()
            self.assertEqual(c.memcache_server, '')
            memcache.return_value = {'memcache_server': 'hello'}
            self.assertEqual(c.memcache_server, 'hello')

    def test_memcache_host(self):
        with mock.patch.object(adapters.APIConfigurationAdapter, 'memcache',
                               new_callable=mock.PropertyMock) as memcache:
            memcache.return_value = {}
            c = adapters.APIConfigurationAdapter()
            self.assertEqual(c.memcache_host, '')
            memcache.return_value = {'memcache_server_formatted': 'hello'}
            self.assertEqual(c.memcache_host, 'hello')

    def test_memcache_port(self):
        with mock.patch.object(adapters.APIConfigurationAdapter, 'memcache',
                               new_callable=mock.PropertyMock) as memcache:
            memcache.return_value = {}
            c = adapters.APIConfigurationAdapter()
            self.assertEqual(c.memcache_port, '')
            memcache.return_value = {'memcache_port': 'hello'}
            self.assertEqual(c.memcache_port, 'hello')

    def test_memcache_url(self):
        with mock.patch.object(adapters.APIConfigurationAdapter, 'memcache',
                               new_callable=mock.PropertyMock) as memcache:
            memcache.return_value = {}
            c = adapters.APIConfigurationAdapter()
            self.assertEqual(c.memcache_url, '')
            memcache.return_value = {'memcache_url': 'hello'}
            self.assertEqual(c.memcache_url, 'hello')

    def test_workers(self):
        class FakeWorkerConfigContext(object):
            def __call__(self):
                return {"workers": 8}

        with mock.patch.object(adapters.ch_context, 'WorkerConfigContext',
                               new=FakeWorkerConfigContext):
            c = adapters.APIConfigurationAdapter()
            self.assertEqual(c.workers, 8)

    def test_wsgi_worker_context(self):
        class ChInstance1(object):
            name = 'test-name'
            wsgi_script = 'test-script'
            api_ports = active_api_ports = {}

        class ChInstance2(object):
            name = 'test-name'
            wsgi_script = 'test-script'
            wsgi_admin_script = 'test-admin-script'
            wsgi_public_script = 'test-public-script'
            wsgi_process_weight = 0.5
            wsgi_admin_process_weight = 0.1
            wsgi_public_process_weight = 0.4
            api_ports = active_api_ports = {}

        class ChInstance3(object):
            name = 'test-name'
            wsgi_script = None
            wsgi_admin_script = 'test-admin-script'
            wsgi_public_script = 'test-public-script'
            wsgi_process_weight = None
            wsgi_admin_process_weight = 0.1
            wsgi_public_process_weight = 0.4
            api_ports = active_api_ports = {}

        class FakeWSGIWorkerConfigContext():
            copy_kwargs = None

            def __init__(self, **kwargs):
                self.__class__.copy_kwargs = kwargs.copy()

            def __call__(self):
                return "T"

        with mock.patch.object(adapters.ch_context, 'WSGIWorkerConfigContext',
                               new=FakeWSGIWorkerConfigContext):
            # start with no charm instance to get default values
            c = adapters.APIConfigurationAdapter()
            self.assertEqual(c.wsgi_worker_context, "T")
            self.assertEqual(FakeWSGIWorkerConfigContext.copy_kwargs, {})
            # start with a minimal charm_instance
            instance = ChInstance1()
            c = adapters.APIConfigurationAdapter(charm_instance=instance)
            self.assertEqual(c.wsgi_worker_context, "T")
            self.assertEqual(FakeWSGIWorkerConfigContext.copy_kwargs,
                             {'name': 'test-name', 'script': 'test-script'})
            # And then, all the options set:
            instance = ChInstance2()
            c = adapters.APIConfigurationAdapter(charm_instance=instance)
            self.assertEqual(c.wsgi_worker_context, "T")
            self.assertEqual(FakeWSGIWorkerConfigContext.copy_kwargs,
                             {'name': 'test-name',
                              'script': 'test-script',
                              'admin_script': 'test-admin-script',
                              'public_script': 'test-public-script',
                              'process_weight': 0.5,
                              'admin_process_weight': 0.1,
                              'public_process_weight': 0.4})
            # and finally, with some of the options set to None, to test
            # filtering
            instance = ChInstance3()
            c = adapters.APIConfigurationAdapter(charm_instance=instance)
            self.assertEqual(c.wsgi_worker_context, "T")
            self.assertEqual(FakeWSGIWorkerConfigContext.copy_kwargs,
                             {'name': 'test-name',
                              'admin_script': 'test-admin-script',
                              'public_script': 'test-public-script',
                              'admin_process_weight': 0.1,
                              'public_process_weight': 0.4})


class FakePeerHARelationAdapter(object):

    def __init__(self, relation=None, relation_name=None):
        self.hadict = {
            'cluster_hosts': {'my': 'map'}}

    def __getitem__(self, arg):
        return self.hadict[arg]

    @property
    def single_mode_map(self):
        return self.hadict


class FakePeerHARelationAdapter2(FakePeerHARelationAdapter):

    @property
    def single_mode_map(self):
        return None


class TestOpenStackRelationAdapters(unittest.TestCase):
    # test the OpenStackRelationAdapters() class, and then derive from it to
    # test the additonal relation_adapters member on __init__

    def test_class(self):
        test_config = {
            'one': 1,
            'two': 2,
            'three': 3,
            'that-one': 4
        }
        with mock.patch.object(adapters, 'PeerHARelationAdapter',
                               new=FakePeerHARelationAdapter), \
                mock.patch.object(adapters.hookenv, 'config',
                                  new=lambda: test_config):
            amqp = FakeRabbitMQRelation()
            shared_db = FakeDatabaseRelation()
            mine = MyRelation()
            a = adapters.OpenStackRelationAdapters([amqp, shared_db, mine])
            self.assertEqual(a.amqp.private_address, 'private-address')
            self.assertEqual(a.my_name.this, 'this')
            # pick the keys off the __iter__() for the adapters instance
            items = [x[0] for x in list(a)]
            self.assertTrue('options' in items)
            # self.assertTrue('cluster' in items)
            self.assertTrue('amqp' in items)
            self.assertTrue('shared_db' in items)
            self.assertTrue('my_name' in items)

    def test_set_charm_instance(self):

        # a fake charm instance to play with
        class FakeCharm(object):
            name = 'fake-charm'

        shared_db = FakeDatabaseRelation()
        charm = FakeCharm()
        a = adapters.OpenStackRelationAdapters([shared_db],
                                               charm_instance=charm)
        self.assertEqual(a.charm_instance, charm)

    def test_custom_configurations_creation(self):
        # Test we can bring in a custom configurations

        class FakeConfigurationAdapter(adapters.ConfigurationAdapter):

            def __init__(self, charm_instance):
                self.test = 'hello'

        class FakeCharm(object):
            name = 'fake-charm'
            configuration_class = FakeConfigurationAdapter

        with mock.patch.object(adapters, '_custom_config_properties', new={}):

            @adapters.config_property
            def custom_prop(config):
                return config.test

            a = adapters.OpenStackRelationAdapters(
                [], charm_instance=FakeCharm())

            self.assertEqual(a.options.custom_prop, 'hello')
            self.assertIsInstance(a.options, FakeConfigurationAdapter)

    def test_hoists_custom_relation_properties(self):

        class FakeConfigurationAdapter(adapters.ConfigurationAdapter):

            def __init__(self, charm_instance):
                pass

        class FakeSharedDBAdapter(adapters.OpenStackRelationAdapter):
            interface_name = 'shared-db'

        class FakeThingAdapter(adapters.OpenStackRelationAdapter):
            interface_name = 'some-interface'

        class FakeAdapters(adapters.OpenStackRelationAdapters):
            # override the relation_adapters to our shared_db adapter
            relation_adapters = {
                'shared-db': FakeSharedDBAdapter,
                'some-interface': FakeThingAdapter,
            }

        class FakeThing(object):
            relation_name = 'some-interface'
            auto_accessors = []

        class FakeSharedDB(object):
            relation_name = 'shared-db'
            auto_accessors = ('thing',)

            def thing(self):
                return 'kenobi'

        class FakeCharm(object):
            name = 'fake-charm'
            adapters_class = FakeAdapters
            configuration_class = FakeConfigurationAdapter

        with mock.patch.object(adapters, '_custom_adapter_properties', {}):

            @adapters.adapter_property('some-interface')
            def custom_property(interface):
                return 'goodbye'

            @adapters.adapter_property('shared-db')
            def custom_thing(shared_db):
                return 'obe wan {}'.format(shared_db.thing)

            shared_db = FakeSharedDB()
            fake_thing = FakeThing()
            a = FakeAdapters([shared_db, fake_thing],
                             charm_instance=FakeCharm())

            # Verify that the custom properties got set.
            # This also checks that all the classes were instantiated
            self.assertEqual(a.some_interface.custom_property, 'goodbye')
            self.assertEqual(a.shared_db.custom_thing, 'obe wan kenobi')

            # verify that the right relations clases were instantiated.
            # Note that this checks that the adapters' inheritence is correct;
            # they are actually modified classes.
            self.assertEqual(len(a._adapters), 2)
            self.assertIsInstance(a.some_interface, FakeThingAdapter)
            self.assertNotEqual(a.some_interface.__class__.__name__,
                                'FakeThingAdapter')
            self.assertIsInstance(a.shared_db, FakeSharedDBAdapter)
            self.assertNotEqual(a.shared_db.__class__.__name__,
                                'FakeSharedDBAdapter')

            # verify that the iteration of the adapters yields the interfaces
            ctxt = dict(a)
            self.assertIsInstance(ctxt['options'], FakeConfigurationAdapter)
            self.assertIsInstance(ctxt['shared_db'], FakeSharedDBAdapter)
            self.assertIsInstance(ctxt['some_interface'], FakeThingAdapter)
            self.assertEqual(len(ctxt.keys()), 3)


class MyRelationAdapter(adapters.OpenStackRelationAdapter):

    @property
    def us(self):
        return self.this + '-us'


class MyOpenStackRelationAdapters(adapters.OpenStackRelationAdapters):

    relation_adapters = {
        'my_name': MyRelationAdapter,
    }


class MyOpenStackAPIRelationAdapters(adapters.OpenStackAPIRelationAdapters):

    relation_adapters = {
        'my_name': MyRelationAdapter,
    }


class MyConfigAdapter(adapters.ConfigurationAdapter):

    def __init__(self, key1=None):
        self.customarg = key1
        self.instancearg = 'instancearg1'


class TestCustomOpenStackRelationAdapters(unittest.TestCase):

    def test_class(self):
        test_config = {
            'one': 1,
            'two': 2,
            'three': 3,
            'that-one': 4
        }
        with mock.patch.object(adapters.hookenv, 'related_units',
                               return_value=[]), \
                mock.patch.object(adapters.hookenv,
                                  'config',
                                  new=lambda: test_config):
            amqp = FakeRabbitMQRelation()
            shared_db = FakeDatabaseRelation()
            mine = MyRelation()
            # Test using deprecated 'options' argument to pass in
            # configuration class
            a = MyOpenStackRelationAdapters([amqp, shared_db, mine],
                                            options=MyConfigAdapter,)
            self.assertEqual(a.my_name.us, 'this-us')
            self.assertEqual(a.options.instancearg, 'instancearg1')
            # Test using 'options_instance' argument to pass in
            # instance of configuration class
            b = MyOpenStackRelationAdapters(
                [amqp, shared_db, mine],
                options_instance=MyConfigAdapter(key1='customarg1'),)
            self.assertEqual(b.my_name.us, 'this-us')
            self.assertEqual(b.options.instancearg, 'instancearg1')
            self.assertEqual(b.options.customarg, 'customarg1')


class TestCustomOpenStackAPIRelationAdapters(unittest.TestCase):

    def test_class(self):
        test_config = {
            'one': 1,
            'two': 2,
            'three': 3,
            'that-one': 4
        }
        with mock.patch.object(adapters.hookenv, 'related_units',
                               return_value=[]), \
                mock.patch.object(adapters.hookenv,
                                  'config',
                                  new=lambda: test_config), \
                mock.patch.object(adapters, 'PeerHARelationAdapter',
                                  new=FakePeerHARelationAdapter):
            amqp = FakeRabbitMQRelation()
            shared_db = FakeDatabaseRelation()
            mine = MyRelation()
            # Test using deprecated 'options' argument to pass in
            # configuration class
            a = MyOpenStackAPIRelationAdapters([amqp, shared_db, mine],
                                               options=MyConfigAdapter,)
            self.assertEqual(a.my_name.us, 'this-us')
            self.assertEqual(a.options.instancearg, 'instancearg1')
            self.assertEqual(a.cluster['cluster_hosts'], {'my': 'map'})
            # Test using 'options_instance' argument to pass in
            # instance of configuration class
            b = MyOpenStackAPIRelationAdapters(
                [amqp, shared_db, mine],
                options_instance=MyConfigAdapter(key1='customarg1'),)
            self.assertEqual(b.my_name.us, 'this-us')
            self.assertEqual(b.options.instancearg, 'instancearg1')
            self.assertEqual(b.options.customarg, 'customarg1')
            self.assertEqual(b.cluster['cluster_hosts'], {'my': 'map'})

    def test_add_cluster(self):
        test_config = {
            'one': 1,
            'two': 2,
            'three': 3,
            'that-one': 4
        }
        with mock.patch.object(adapters.hookenv, 'related_units',
                               return_value=[]), \
                mock.patch.object(adapters.hookenv,
                                  'config',
                                  new=lambda: test_config), \
                mock.patch.object(adapters.relations, 'endpoint_from_flag',
                                  new=FakePeerHARelationAdapter), \
                mock.patch.object(adapters, 'PeerHARelationAdapter',
                                  new=FakePeerHARelationAdapter2):
            b = MyOpenStackAPIRelationAdapters([])
            self.assertEqual(b.cluster['cluster_hosts'], {'my': 'map'})
