# Note that the unit_tests/__init__.py has the following lines to stop
# side effects from the imorts from charm helpers.

# sys.path.append('./lib')
# mock out some charmhelpers libraries as they have apt install side effects
# sys.modules['charmhelpers.contrib.openstack.utils'] = mock.MagicMock()
# sys.modules['charmhelpers.contrib.network.ip'] = mock.MagicMock()

import copy
import unittest
import mock

import charms_openstack.adapters as adapters


class MyRelation(object):

    auto_accessors = ['this', 'that']
    relation_name = 'my-name'

    def this(self):
        return 'this'

    def that(self):
        return 'that'

    def some(self):
        return 'thing'


class TestOpenStackRelationAdapter(unittest.TestCase):

    def test_class(self):
        ad = adapters.OpenStackRelationAdapter(MyRelation(), ['some'])
        self.assertEqual(ad.this, 'this')
        self.assertEqual(ad.that, 'that')
        self.assertEqual(ad.some, 'thing')
        self.assertEqual(ad.relation_name, 'my-name')
        with self.assertRaises(AttributeError):
            ad.relation_name = 'hello'

    def test_class_no_relation(self):
        ad = adapters.OpenStackRelationAdapter(relation_name='cluster')
        self.assertEqual(ad.relation_name, 'cluster')


class FakeRabbitMQRelation():

    auto_accessors = ['vip', 'private_address']
    relation_name = 'amqp'

    def __init__(self, vip=None):
        self._vip = vip

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


class TestRabbitMQRelationAdapter(unittest.TestCase):

    def test_class(self):
        fake = FakeRabbitMQRelation(None)
        mq = adapters.RabbitMQRelationAdapter(fake)
        self.assertEqual(mq.vhost, 'vhost')
        self.assertEqual(mq.username, 'fakename')
        self.assertEqual(mq.host, 'private-address')
        # TODO: can't do the following 2 lines as not dynamic accessors
        # fake._vip = 'vip1'
        # self.assertEqual(mq.host, 'vip1')
        self.assertEqual(mq.hosts, 'host1,host2')


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
            'int-address': [
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
        with mock.patch.object(adapters.ch_ip, 'get_address_in_network',
                               new=lambda x: test_addresses.get(x)), \
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
            # Test single_mode_map when a cluster relation is present
            with mock.patch.object(adapters.hookenv, 'relation_ids',
                                   new=lambda x: ['rid1']), \
                    mock.patch.object(adapters.hookenv, 'related_units',
                                      new=lambda relid: []):
                expect = {'cluster_hosts': expect_local_ns}
                expect['cluster_hosts']['this_unit_private_addr'] = \
                    expect_local_default['this_unit_private_addr']
                peer_ra = adapters.PeerHARelationAdapter(FakePeerRelation())
                self.assertEqual(peer_ra.single_mode_map, expect)
            # Test single_mode_map when a cluster relation is not present
            with mock.patch.object(adapters.hookenv, 'relation_ids',
                                   new=lambda x: []):
                peer_ra = adapters.PeerHARelationAdapter(FakePeerRelation())
                self.assertEqual(peer_ra.single_mode_map, {})


class FakeDatabaseRelation():

    auto_accessors = []
    relation_name = 'shared_db'

    def db_host(self):
        return 'host1'

    def username(self, prefix=''):
        return 'username1{}'.format(prefix)

    def password(self, prefix=''):
        return 'password1{}'.format(prefix)

    def database(self, prefix=''):
        return 'database1{}'.format(prefix)


class SSLDatabaseRelationAdapter(adapters.DatabaseRelationAdapter):

    ssl_ca = 'my-ca'
    ssl_cert = 'my-cert'
    ssl_key = 'my-key'


class TestDatabaseRelationAdapter(unittest.TestCase):

    def test_class(self):
        fake = FakeDatabaseRelation()
        db = adapters.DatabaseRelationAdapter(fake)
        self.assertEqual(db.host, 'host1')
        self.assertEqual(db.type, 'mysql')
        self.assertEqual(db.password, 'password1')
        self.assertEqual(db.username, 'username1')
        self.assertEqual(db.database, 'database1')
        self.assertEqual(db.uri, 'mysql://username1:password1@host1/database1')
        self.assertEqual(db.get_uri('x'),
                         'mysql://username1x:password1x@host1/database1x')
        # test the ssl feature of the base class
        db = SSLDatabaseRelationAdapter(fake)
        self.assertEqual(db.uri,
                         'mysql://username1:password1@host1/database1'
                         '?ssl_ca=my-ca'
                         '&ssl_cert=my-cert&ssl_key=my-key')


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


class TestAPIConfigurationAdapter(unittest.TestCase):
    api_ports = {
        'svc1': {
            'admin': 9001,
            'public': 9001,
            'internal': 9001,
        },
        'svc2': {
            'admin': 9002,
            'public': 9002,
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

    def test_ipv4_mode(self):
        test_config = {
            'prefer-ipv6': False,
            'vip': '',
        }
        with mock.patch.object(adapters.ch_utils, 'get_host_ip',
                               return_value='10.0.0.10'), \
                mock.patch.object(adapters.hookenv, 'config',
                                  new=lambda: test_config), \
                mock.patch.object(adapters.hookenv, 'unit_get',
                                  return_value='10.0.0.20'), \
                mock.patch.object(adapters.APIConfigurationAdapter,
                                  'get_network_addresses'):
            c = adapters.APIConfigurationAdapter(service_name='svc1')
            self.assertFalse(c.ipv6_mode)
            self.assertEqual(c.local_address, '10.0.0.10')
            self.assertEqual(c.local_host, '127.0.0.1')
            self.assertEqual(c.haproxy_host, '0.0.0.0')
            self.assertEqual(c.service_name, 'svc1')

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

    def test_external_ports(self):
        c = adapters.APIConfigurationAdapter(port_map=self.api_ports)
        self.assertEqual(c.external_ports, {9001, 9002})

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
                               new=lambda: test_config), \
                mock.patch.object(adapters.hookenv, 'unit_get',
                                  return_value='thisunit'), \
                mock.patch.object(adapters.os_ip, 'resolve_address',
                                  new=_resolve_address), \
                mock.patch.object(adapters.ch_ip, 'get_address_in_network',
                                  new=lambda x, y: test_networks[x]):
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

        test_config = {
            'prefer-ipv6': False,
            'vip': '10.10.10.10',
            'private-address': 'privaddr',
        }

        def _determine_apache_port(port, singlenode_mode=None):
            return port - 10

        with mock.patch.object(adapters.ch_cluster, 'determine_apache_port',
                               side_effect=_determine_apache_port), \
                mock.patch.object(adapters.APIConfigurationAdapter,
                                  'determine_service_port',
                                  side_effect=_determine_apache_port), \
                mock.patch.object(adapters.APIConfigurationAdapter,
                                  'get_network_addresses'), \
                mock.patch.object(adapters.hookenv, 'config',
                                  new=lambda: test_config):
            with mock.patch.object(adapters.APIConfigurationAdapter,
                                   'apache_enabled',
                                   new=False):
                c = MockAddrAPIConfigurationAdapt(port_map=self.api_ports)
                self.assertEqual(
                    c.service_ports,
                    {'svc1': [9001, 8991], 'svc2': [9002, 8992]})
                self.assertEqual(
                    c.service_listen_info, {
                        'svc1': {
                            'proto': 'http',
                            'ip': '10.0.0.10',
                            'port': 8991,
                            'url': 'http://10.0.0.10:8991'},
                        'svc2': {
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
                    {'svc1': [9001, 8991], 'svc2': [9002, 8992]})
                self.assertEqual(
                    c.service_listen_info, {
                        'svc1': {
                            'proto': 'http',
                            'ip': '127.0.0.1',
                            'port': 8991,
                            'url': 'http://127.0.0.1:8991'},
                        'svc2': {
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
                ('internal_addr', 'vip_internal_net', 8991, 8981),
                ('internal_addr', 'vip_internal_net', 8992, 8982)
            ]

            self.assertEqual(c.endpoints, expect)
            self.assertEqual(c.ext_ports, [8991, 8992])

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


class FakePeerHARelationAdapter(object):

    def __init__(self, relation=None, relation_name=None):
        pass

    @property
    def single_mode_map(self):
        return {'cluster_hosts': {'my': 'map'}}


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
            items = list(a)
            self.assertEqual(items[0][0], 'options')
            self.assertEqual(items[1][0], 'cluster')
            self.assertEqual(items[2][0], 'amqp')
            self.assertEqual(items[3][0], 'shared_db')
            self.assertEqual(items[4][0], 'my_name')


class MyRelationAdapter(adapters.OpenStackRelationAdapter):

    @property
    def us(self):
        return self.this + '-us'


class MyOpenStackRelationAdapters(adapters.OpenStackRelationAdapters):

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
                                  new=lambda: test_config), \
                mock.patch.object(adapters, 'PeerHARelationAdapter',
                                  new=FakePeerHARelationAdapter):
            amqp = FakeRabbitMQRelation()
            shared_db = FakeDatabaseRelation()
            mine = MyRelation()
            # Test using deprecated 'options' argument to pass in
            # configuration class
            a = MyOpenStackRelationAdapters([amqp, shared_db, mine],
                                            options=MyConfigAdapter,)
            self.assertEqual(a.my_name.us, 'this-us')
            self.assertEqual(a.options.instancearg, 'instancearg1')
            self.assertEqual(a.cluster['cluster_hosts'], {'my': 'map'})
            # Test using 'options_instance' argument to pass in
            # instance of configuration class
            b = MyOpenStackRelationAdapters(
                [amqp, shared_db, mine],
                options_instance=MyConfigAdapter(key1='customarg1'),)
            self.assertEqual(b.my_name.us, 'this-us')
            self.assertEqual(b.options.instancearg, 'instancearg1')
            self.assertEqual(b.options.customarg, 'customarg1')
            self.assertEqual(a.cluster['cluster_hosts'], {'my': 'map'})
