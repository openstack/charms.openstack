# Note that the unit_tests/__init__.py has the following lines to stop
# side effects from the imorts from charm helpers.

# mock out some charmhelpers libraries as they have apt install side effects
# sys.modules['charmhelpers.contrib.openstack.utils'] = mock.MagicMock()
# sys.modules['charmhelpers.contrib.network.ip'] = mock.MagicMock()
from __future__ import absolute_import

import base64
import collections
import unittest

import mock

import unit_tests.utils as utils

import charms_openstack.charm as chm

TEST_CONFIG = {'config': True}


class BaseOpenStackCharmTest(utils.BaseTestCase):

    @classmethod
    def setUpClass(cls):
        cls.patched_config = mock.patch.object(chm.hookenv, 'config')
        cls.patched_config_started = cls.patched_config.start()

    @classmethod
    def tearDownClass(cls):
        cls.patched_config.stop()
        cls.patched_config_started = None
        cls.patched_config = None

    def setUp(self, target_cls, test_config):
        super(BaseOpenStackCharmTest, self).setUp()
        # set up the return value on the mock before instantiating the class to
        # get the config into the class.config.
        chm.hookenv.config.return_value = test_config
        self.target = target_cls()

    def tearDown(self):
        self.target = None
        # if we've created a singleton on the module, also destroy that.
        chm._singleton = None
        super(BaseOpenStackCharmTest, self).tearDown()

    def patch_target(self, attr, return_value=None, name=None, new=None):
        # uses BaseTestCase.patch_object() to patch targer.
        self.patch_object(self.target, attr, return_value, name, new)


class TestOpenStackCharmMeta(BaseOpenStackCharmTest):

    def setUp(self):
        super(TestOpenStackCharmMeta, self).setUp(
            chm.OpenStackCharm, TEST_CONFIG)

    def test_register_classes(self):
        self.patch_object(chm, '_releases', new={})

        class TestC1(chm.OpenStackCharm):
            release = 'liberty'

        class TestC2(chm.OpenStackCharm):
            release = 'mitaka'

        self.assertTrue('liberty' in chm._releases.keys())
        self.assertTrue('mitaka' in chm._releases.keys())
        self.assertEqual(chm._releases['liberty'], TestC1)
        self.assertEqual(chm._releases['mitaka'], TestC2)

    def test_register_unknown_series(self):
        self.patch_object(chm, '_releases', new={})
        with self.assertRaises(RuntimeError):
            class TestC1(chm.OpenStackCharm):
                release = 'unknown'

    def test_register_repeated_series(self):
        self.patch_object(chm, '_releases', new={})
        with self.assertRaises(RuntimeError):
            class TestC1(chm.OpenStackCharm):
                release = 'liberty'

            class TestC2(chm.OpenStackCharm):
                release = 'liberty'


class TestFunctions(BaseOpenStackCharmTest):

    def setUp(self):
        super(TestFunctions, self).setUp(
            chm.OpenStackCharm, TEST_CONFIG)
        self.patch_object(chm, '_releases', new={})

        class TestC1(chm.OpenStackCharm):
            release = 'icehouse'

        class TestC2(chm.OpenStackCharm):
            release = 'kilo'

        class TestC3(chm.OpenStackCharm):
            release = 'mitaka'

        self.C1, self.C2, self.C3 = TestC1, TestC2, TestC3

    def test_get_exact(self):
        self.assertTrue(
            isinstance(chm.get_charm_instance(release='icehouse'), self.C1))
        self.assertTrue(
            isinstance(chm.get_charm_instance(release='mitaka'), self.C3))

    def test_get_inbetween(self):
        self.assertTrue(
            isinstance(chm.get_charm_instance(release='juno'), self.C1))

    def test_fail_too_early_series(self):
        with self.assertRaises(RuntimeError):
            chm.get_charm_instance(release='havana')

    def test_get_default_release(self):
        # TODO this may be the wrong logic.  Assume latest release if no
        # release is passed?
        self.assertTrue(isinstance(chm.get_charm_instance(), self.C3))


class TestRegisterOSReleaseSelector(unittest.TestCase):

    def test_register(self):
        save_rsf = chm._release_selector_function
        chm._release_selector_function = None

        @chm.register_os_release_selector
        def test_func():
            pass

        self.assertEqual(chm._release_selector_function, test_func)
        chm._release_selector_function = save_rsf

    def test_cant_register_more_than_once(self):
        save_rsf = chm._release_selector_function
        chm._release_selector_function = None

        @chm.register_os_release_selector
        def test_func1():
            pass

        with self.assertRaises(RuntimeError):
            @chm.register_os_release_selector
            def test_func2():
                pass

        self.assertEqual(chm._release_selector_function, test_func1)
        chm._release_selector_function = save_rsf


class TestOpenStackCharm(BaseOpenStackCharmTest):
    # Note that this only tests the OpenStackCharm() class, which has not very
    # useful defaults for testing.  In order to test all the code without too
    # many mocks, a separate test dervied charm class is used below.

    def setUp(self):
        super(TestOpenStackCharm, self).setUp(chm.OpenStackCharm, TEST_CONFIG)

    def test__init__(self):
        # Note cls.setUpClass() creates an OpenStackCharm() instance
        self.assertEqual(chm.hookenv.config(), TEST_CONFIG)
        self.assertEqual(self.target.config, TEST_CONFIG)
        # Note that we assume NO release unless given one.
        self.assertEqual(self.target.release, None)

    def test_install(self):
        # only tests that the default set_state is called
        self.patch_target('set_state')
        self.patch_object(chm.charmhelpers.fetch,
                          'filter_installed_packages',
                          name='fip',
                          return_value=None)
        self.target.install()
        self.target.set_state.assert_called_once_with('charmname-installed')
        self.fip.assert_called_once_with([])

    def test_all_packages(self):
        self.assertEqual(self.target.packages, self.target.all_packages)

    def test_full_restart_map(self):
        self.assertEqual(self.target.full_restart_map, self.target.restart_map)

    def test_set_state(self):
        # tests that OpenStackCharm.set_state() calls set_state() global
        self.patch_object(chm.charms.reactive.bus, 'set_state')
        self.target.set_state('hello')
        self.set_state.assert_called_once_with('hello', None)
        self.set_state.reset_mock()
        self.target.set_state('hello', 'there')
        self.set_state.assert_called_once_with('hello', 'there')

    def test_remove_state(self):
        # tests that OpenStackCharm.remove_state() calls remove_state() global
        self.patch_object(chm.charms.reactive.bus, 'remove_state')
        self.target.remove_state('hello')
        self.remove_state.assert_called_once_with('hello')

    def test_configure_source(self):
        self.patch_object(chm.os_utils,
                          'configure_installation_source',
                          name='cis')
        self.patch_object(chm.charmhelpers.fetch, 'apt_update')
        self.patch_target('config', new={'openstack-origin': 'an-origin'})
        self.target.configure_source()
        self.cis.assert_called_once_with('an-origin')
        self.apt_update.assert_called_once_with(fatal=True)

    def test_region(self):
        self.patch_target('config', new={'region': 'a-region'})
        self.assertEqual(self.target.region, 'a-region')

    def test_restart_on_change(self):
        from collections import OrderedDict
        hashs = OrderedDict([
            ('path1', 100),
            ('path2', 200),
            ('path3', 300),
            ('path4', 400),
        ])
        self.target.restart_map = {
            'path1': ['s1'],
            'path2': ['s2'],
            'path3': ['s3'],
            'path4': ['s2', 's4'],
        }
        self.patch_object(chm.ch_host, 'path_hash')
        self.path_hash.side_effect = lambda x: hashs[x]
        self.patch_object(chm.ch_host, 'service_stop')
        self.patch_object(chm.ch_host, 'service_start')
        # slightly awkard, in that we need to test a context manager
        with self.target.restart_on_change():
            # test with no restarts
            pass
        self.assertEqual(self.service_stop.call_count, 0)
        self.assertEqual(self.service_start.call_count, 0)

        with self.target.restart_on_change():
            # test with path1 and path3 restarts
            for k in ['path1', 'path3']:
                hashs[k] += 1
        self.assertEqual(self.service_stop.call_count, 2)
        self.assertEqual(self.service_start.call_count, 2)
        self.service_stop.assert_any_call('s1')
        self.service_stop.assert_any_call('s3')
        self.service_start.assert_any_call('s1')
        self.service_start.assert_any_call('s3')

        # test with path2 and path4 and that s2 only gets restarted once
        self.service_stop.reset_mock()
        self.service_start.reset_mock()
        with self.target.restart_on_change():
            for k in ['path2', 'path4']:
                hashs[k] += 1
        self.assertEqual(self.service_stop.call_count, 2)
        self.assertEqual(self.service_start.call_count, 2)
        calls = [mock.call('s2'), mock.call('s4')]
        self.service_stop.assert_has_calls(calls)
        self.service_start.assert_has_calls(calls)

    def test_restart_all(self):
        self.patch_object(chm.ch_host, 'service_restart')
        self.patch_target('services', new=['s1', 's2'])
        self.target.restart_all()
        self.assertEqual(self.service_restart.call_args_list,
                         [mock.call('s1'), mock.call('s2')])

    def test_db_sync_done(self):
        self.patch_object(chm.hookenv, 'leader_get')
        self.leader_get.return_value = True
        self.assertTrue(self.target.db_sync_done())
        self.leader_get.return_value = False
        self.assertFalse(self.target.db_sync_done())

    def test_db_sync(self):
        self.patch_object(chm.hookenv, 'is_leader')
        self.patch_object(chm.hookenv, 'leader_get')
        self.patch_object(chm.hookenv, 'leader_set')
        self.patch_object(chm, 'subprocess', name='subprocess')
        self.patch_target('restart_all')
        # first check with leader_get returning True
        self.leader_get.return_value = True
        self.is_leader.return_value = True
        self.target.db_sync()
        self.leader_get.assert_called_once_with(attribute='db-sync-done')
        self.subprocess.check_call.assert_not_called()
        self.leader_set.assert_not_called()
        # Now check with leader_get returning False
        self.leader_get.reset_mock()
        self.leader_get.return_value = False
        self.target.sync_cmd = ['a', 'cmd']
        self.target.db_sync()
        self.leader_get.assert_called_once_with(attribute='db-sync-done')
        self.subprocess.check_call.assert_called_once_with(['a', 'cmd'])
        self.leader_set.assert_called_once_with({'db-sync-done': True})
        # Now check with is_leader returning False
        self.leader_set.reset_mock()
        self.subprocess.check_call.reset_mock()
        self.leader_get.return_value = True
        self.is_leader.return_value = False
        self.target.db_sync()
        self.subprocess.check_call.assert_not_called()
        self.leader_set.assert_not_called()


class TestHAOpenStackCharm(BaseOpenStackCharmTest):
    # Note that this only tests the OpenStackCharm() class, which has not very
    # useful defaults for testing.  In order to test all the code without too
    # many mocks, a separate test dervied charm class is used below.

    def setUp(self):
        super(TestHAOpenStackCharm, self).setUp(chm.HAOpenStackCharm,
                                                TEST_CONFIG)

    def test_haproxy_enabled(self):
        self.patch_target('ha_resources', new=['haproxy'])
        self.assertTrue(self.target.haproxy_enabled())

    def test__init__(self):
        # Note cls.setUpClass() creates an OpenStackCharm() instance
        self.assertEqual(chm.hookenv.config(), TEST_CONFIG)
        self.assertEqual(self.target.config, TEST_CONFIG)
        # Note that we assume NO release unless given one.
        self.assertEqual(self.target.release, None)

    def test_configure_ha_resources(self):
        interface_mock = mock.Mock()
        self.patch_target('config', new={'vip_iface': 'ens12'})
        self.patch_target('ha_resources', new=['haproxy', 'vips'])
        self.patch_target('_add_ha_vips_config')
        self.patch_target('_add_ha_haproxy_config')
        self.target.configure_ha_resources(interface_mock)
        self._add_ha_vips_config.assert_called_once_with(interface_mock)
        self._add_ha_haproxy_config.assert_called_once_with(interface_mock)
        interface_mock.bind_resources.assert_called_once_with(iface='ens12')

    def test__add_ha_vips_config(self):
        ifaces = {
            'vip1': 'eth1',
            'vip2': 'eth2'}
        masks = {
            'vip1': 'netmask1',
            'vip2': 'netmask2'}
        interface_mock = mock.Mock()
        self.patch_target('name', new='myservice')
        self.patch_target('config', new={'vip': 'vip1 vip2'})
        self.patch_object(chm.ch_ip, 'get_iface_for_address')
        self.get_iface_for_address.side_effect = lambda x: ifaces[x]
        self.patch_object(chm.ch_ip, 'get_netmask_for_address')
        self.get_netmask_for_address.side_effect = lambda x: masks[x]
        self.target._add_ha_vips_config(interface_mock)
        calls = [
            mock.call('myservice', 'vip1', 'eth1', 'netmask1'),
            mock.call('myservice', 'vip2', 'eth2', 'netmask2')]
        interface_mock.add_vip.assert_has_calls(calls)

    def test__add_ha_vips_config_fallback(self):
        config = {
            'vip_cidr': 'user_cidr',
            'vip_iface': 'user_iface',
            'vip': 'vip1 vip2'}
        interface_mock = mock.Mock()
        self.patch_target('name', new='myservice')
        self.patch_target('config', new=config)
        self.patch_object(chm.ch_ip, 'get_iface_for_address')
        self.patch_object(chm.ch_ip, 'get_netmask_for_address')
        self.get_iface_for_address.return_value = None
        self.get_netmask_for_address.return_value = None
        self.target._add_ha_vips_config(interface_mock)
        calls = [
            mock.call('myservice', 'vip1', 'user_iface', 'user_cidr'),
            mock.call('myservice', 'vip2', 'user_iface', 'user_cidr')]
        interface_mock.add_vip.assert_has_calls(calls)

    def test__add_ha_haproxy_config(self):
        self.patch_target('name', new='myservice')
        interface_mock = mock.Mock()
        self.target._add_ha_haproxy_config(interface_mock)
        interface_mock.add_init_service.assert_called_once_with(
            'myservice',
            'haproxy')

    def test_set_haproxy_stat_password(self):
        self.patch_object(chm.charms.reactive.bus, 'get_state')
        self.patch_object(chm.charms.reactive.bus, 'set_state')
        self.get_state.return_value = None
        self.target.set_haproxy_stat_password()
        self.set_state.assert_called_once_with('haproxy.stat.password',
                                               mock.ANY)

    def test_hacharm_all_packages(self):
        self.patch_target('haproxy_enabled', return_value=True)
        self.assertTrue('haproxy' in self.target.all_packages)
        self.patch_target('haproxy_enabled', return_value=False)
        self.assertFalse('haproxy' in self.target.all_packages)

    def test_hacharm_full_restart_map(self):
        self.patch_target('haproxy_enabled', return_value=True)
        self.assertTrue(
            self.target.full_restart_map.get(
                '/etc/haproxy/haproxy.cfg', False))

    def test_enable_apache_ssl_vhost(self):
        self.patch_object(chm.os.path, 'exists', return_value=True)
        self.patch_object(chm.subprocess, 'call', return_value=1)
        self.patch_object(chm.subprocess, 'check_call')
        self.target.enable_apache_ssl_vhost()
        self.check_call.assert_called_once_with(
            ['a2ensite', 'openstack_https_frontend'])
        self.check_call.reset_mock()
        self.patch_object(chm.subprocess, 'call', return_value=0)
        self.target.enable_apache_ssl_vhost()
        self.assertFalse(self.check_call.called)

    def test_enable_apache_modules(self):
        apache_mods = {
            'ssl': 0,
            'proxy': 0,
            'proxy_http': 1}
        self.patch_object(chm.ch_host, 'service_restart')
        self.patch_object(chm.subprocess, 'check_call')
        self.patch_object(
            chm.subprocess, 'call',
            new=lambda x: apache_mods[x.pop()])
        self.target.enable_apache_modules()
        self.check_call.assert_called_once_with(
            ['a2enmod', 'proxy_http'])
        self.service_restart.assert_called_once_with('apache2')

    def test_configure_cert(self):
        self.patch_object(chm.ch_host, 'mkdir')
        self.patch_object(chm.ch_host, 'write_file')
        self.target.configure_cert('mycert', 'mykey', cn='mycn')
        self.mkdir.assert_called_once_with(path='/etc/apache2/ssl/charmname')
        calls = [
            mock.call(
                path='/etc/apache2/ssl/charmname/cert_mycn',
                content=b'mycert'),
            mock.call(
                path='/etc/apache2/ssl/charmname/key_mycn',
                content=b'mykey')]
        self.write_file.assert_has_calls(calls)
        self.write_file.reset_mock()
        self.patch_object(chm.os_ip, 'resolve_address', 'addr')
        self.target.configure_cert('mycert', 'mykey')
        calls = [
            mock.call(
                path='/etc/apache2/ssl/charmname/cert_addr',
                content=b'mycert'),
            mock.call(
                path='/etc/apache2/ssl/charmname/key_addr',
                content=b'mykey')]
        self.write_file.assert_has_calls(calls)

    def test_get_local_addresses(self):
        self.patch_object(chm.os_utils, 'get_host_ip', return_value='privaddr')
        self.patch_object(chm.os_ip, 'resolve_address')
        addresses = {
            'admin': 'admin_addr',
            'int': 'internal_addr',
            'public': 'public_addr'}
        self.resolve_address.side_effect = \
            lambda endpoint_type=None: addresses[endpoint_type]
        self.assertEqual(
            self.target.get_local_addresses(),
            ['admin_addr', 'internal_addr', 'privaddr', 'public_addr'])

    def test_get_certs_and_keys(self):
        self.patch_target(
            'config_defined_ssl_cert',
            new=b'cert')
        self.patch_target(
            'config_defined_ssl_key',
            new=b'key')
        self.patch_target(
            'config_defined_ssl_ca',
            new=b'ca')
        self.assertEqual(
            self.target.get_certs_and_keys(),
            [{'key': 'key', 'cert': 'cert', 'ca': 'ca', 'cn': None}])

    def test_get_certs_and_keys_ks_interface(self):
        class KSInterface(object):
            def get_ssl_key(self, key):
                keys = {
                    'int_addr': 'int_key',
                    'priv_addr': 'priv_key',
                    'pub_addr': 'pub_key',
                    'admin_addr': 'admin_key'}
                return keys[key]

            def get_ssl_cert(self, key):
                certs = {
                    'int_addr': 'int_cert',
                    'priv_addr': 'priv_cert',
                    'pub_addr': 'pub_cert',
                    'admin_addr': 'admin_cert'}
                return certs[key]

            def get_ssl_ca(self):
                return 'ca'

        self.patch_target(
            'get_local_addresses',
            return_value=['int_addr', 'priv_addr', 'pub_addr', 'admin_addr'])
        expect = [
            {
                'ca': 'ca',
                'cert': 'int_cert',
                'cn': 'int_addr',
                'key': 'int_key'},
            {
                'ca': 'ca',
                'cert': 'priv_cert',
                'cn': 'priv_addr',
                'key': 'priv_key'},
            {
                'ca': 'ca',
                'cert': 'pub_cert',
                'cn': 'pub_addr',
                'key': 'pub_key'},
            {
                'ca': 'ca',
                'cert': 'admin_cert',
                'cn': 'admin_addr',
                'key': 'admin_key'}]

        self.assertEqual(
            self.target.get_certs_and_keys(keystone_interface=KSInterface()),
            expect)

    def test_set_config_defined_certs_and_keys(self):
        config = {
            'ssl_key': base64.b64encode(b'confkey'),
            'ssl_cert': base64.b64encode(b'confcert'),
            'ssl_ca': base64.b64encode(b'confca')}
        self.patch_target('config', new=config)
        self.target.set_config_defined_certs_and_keys()
        self.assertEqual(self.target.config_defined_ssl_key, b'confkey')
        self.assertEqual(self.target.config_defined_ssl_cert, b'confcert')
        self.assertEqual(self.target.config_defined_ssl_ca, b'confca')

    def test_configure_ssl(self):
        ssl_objs = [
            {
                'cert': 'cert1',
                'key': 'key1',
                'ca': 'ca1',
                'cn': 'cn1'},
            {
                'cert': 'cert2',
                'key': 'key2',
                'ca': 'ca2',
                'cn': 'cn2'}]
        self.patch_target('get_certs_and_keys', return_value=ssl_objs)
        self.patch_target('configure_apache')
        self.patch_target('configure_cert')
        self.patch_target('configure_ca')
        self.patch_target('run_update_certs')
        self.patch_object(chm.charms.reactive.bus, 'set_state')
        self.target.configure_ssl()
        cert_calls = [
            mock.call('cert1', 'key1', cn='cn1'),
            mock.call('cert2', 'key2', cn='cn2')]
        ca_calls = [
            mock.call('ca1', update_certs=False),
            mock.call('ca2', update_certs=False)]
        self.configure_cert.assert_has_calls(cert_calls)
        self.configure_ca.assert_has_calls(ca_calls)
        self.run_update_certs.assert_called_once_with()
        self.configure_apache.assert_called_once_with()
        self.set_state.assert_called_once_with('ssl.enabled', True)

    def test_configure_ssl_off(self):
        self.patch_target('get_certs_and_keys', return_value=[])
        self.patch_object(chm.charms.reactive.bus, 'set_state')
        self.target.configure_ssl()
        self.set_state.assert_called_once_with('ssl.enabled', False)

    def test_configure_ca(self):
        self.patch_target('run_update_certs')
        with utils.patch_open() as (mock_open, mock_file):
            self.target.configure_ca('myca')
            mock_open.assert_called_with(
                '/usr/local/share/ca-certificates/keystone_juju_ca_cert.crt',
                'w')
            mock_file.write.assert_called_with('myca')
            self.run_update_certs.assert_called_once_with()

    def test_run_update_certs(self):
        self.patch_object(chm.subprocess, 'check_call')
        self.target.run_update_certs()
        self.check_call.assert_called_once_with(
            ['update-ca-certificates', '--fresh'])


class MyAdapter(object):

    def __init__(self, interfaces):
        self.interfaces = interfaces


# force the series to just contain my-series.
# NOTE that this is mocked out in the __init__.py for the unit_tests package
chm.os_utils.OPENSTACK_CODENAMES = collections.OrderedDict([
    ('2011.2', 'my-series'),
])


class MyOpenStackCharm(chm.OpenStackCharm):

    release = 'icehouse'
    name = 'my-charm'
    packages = ['p1', 'p2', 'p3', 'package-to-filter']
    api_ports = {
        'service1': {
            chm.os_ip.PUBLIC: 1,
            chm.os_ip.INTERNAL: 2,
        },
        'service2': {
            chm.os_ip.PUBLIC: 3,
        },
        'my-default-service': {
            chm.os_ip.PUBLIC: 1234,
            chm.os_ip.ADMIN: 2468,
            chm.os_ip.INTERNAL: 3579,
        },
    }
    service_type = 'my-service-type'
    default_service = 'my-default-service'
    restart_map = {
        'path1': ['s1'],
        'path2': ['s2'],
        'path3': ['s3'],
        'path4': ['s2', 's4'],
    }
    sync_cmd = ['my-sync-cmd', 'param1']
    services = ['my-default-service', 'my-second-service']
    adapters_class = MyAdapter


class MyNextOpenStackCharm(MyOpenStackCharm):

    release = 'mitaka'


class TestMyOpenStackCharm(BaseOpenStackCharmTest):

    def setUp(self):
        def make_open_stack_charm():
            return MyOpenStackCharm(['interface1', 'interface2'])

        super(TestMyOpenStackCharm, self).setUp(make_open_stack_charm,
                                                TEST_CONFIG)

    def test_singleton(self):
        # because we have two releases, we expect this to be the latter.
        # e.g. MyNextOpenStackCharm
        s = self.target.singleton
        self.assertEqual(s.__class__.release, 'mitaka')
        self.assertTrue(isinstance(s, MyOpenStackCharm))
        # should also be the second one, as it's the latest
        self.assertTrue(isinstance(s, MyNextOpenStackCharm))
        self.assertTrue(isinstance(MyOpenStackCharm.singleton,
                                   MyOpenStackCharm))
        self.assertTrue(isinstance(chm.OpenStackCharm.singleton,
                                   MyOpenStackCharm))
        self.assertEqual(s, chm.OpenStackCharm.singleton)
        # Note that get_charm_instance() returns NEW instance each time.
        self.assertNotEqual(s, chm.get_charm_instance())
        # now clear out the singleton and make sure we get the first one using
        # a release function
        rsf_save = chm._release_selector_function
        chm._release_selector_function = None

        @chm.register_os_release_selector
        def selector():
            return 'icehouse'

        # This should choose the icehouse version instead of the mitaka version
        chm._singleton = None
        s = self.target.singleton
        self.assertEqual(s.release, 'icehouse')
        self.assertEqual(s.__class__.release, 'icehouse')
        self.assertFalse(isinstance(s, MyNextOpenStackCharm))
        chm._release_selector_function = rsf_save

    def test_install(self):
        # tests that the packages are filtered before installation
        self.patch_target('set_state')
        self.patch_object(chm.charmhelpers.fetch,
                          'filter_installed_packages',
                          return_value=None,
                          name='fip')
        self.fip.side_effect = lambda x: ['p1', 'p2']
        self.patch_object(chm.hookenv, 'status_set')
        self.patch_object(chm.hookenv, 'apt_install')
        self.target.install()
        self.target.set_state.assert_called_once_with('my-charm-installed')
        self.fip.assert_called_once_with(self.target.packages)
        self.status_set.assert_has_calls([
            mock.call('maintenance', 'Installing packages'),
            mock.call('maintenance',
                      'Installation complete - awaiting next status')])

    def test_api_port(self):
        self.assertEqual(self.target.api_port('service1'), 1)
        self.assertEqual(self.target.api_port('service1', chm.os_ip.PUBLIC), 1)
        self.assertEqual(self.target.api_port('service2'), 3)
        with self.assertRaises(KeyError):
            self.target.api_port('service3')
        with self.assertRaises(KeyError):
            self.target.api_port('service2', chm.os_ip.INTERNAL)

    def test_public_url(self):
        self.patch_object(chm.os_ip,
                          'canonical_url',
                          return_value='my-ip-address')
        self.assertEqual(self.target.public_url, 'my-ip-address:1234')
        self.canonical_url.assert_called_once_with(chm.os_ip.PUBLIC)

    def test_admin_url(self):
        self.patch_object(chm.os_ip,
                          'canonical_url',
                          return_value='my-ip-address')
        self.assertEqual(self.target.admin_url, 'my-ip-address:2468')
        self.canonical_url.assert_called_once_with(chm.os_ip.ADMIN)

    def test_internal_url(self):
        self.patch_object(chm.os_ip,
                          'canonical_url',
                          return_value='my-ip-address')
        self.assertEqual(self.target.internal_url, 'my-ip-address:3579')
        self.canonical_url.assert_called_once_with(chm.os_ip.INTERNAL)

    def test_render_all_configs(self):
        self.patch_target('render_configs')
        self.target.render_all_configs()
        self.assertEqual(self.render_configs.call_count, 1)
        args = self.render_configs.call_args_list[0][0][0]
        self.assertEqual(['path1', 'path2', 'path3', 'path4'],
                         sorted(args))

    def test_render_configs(self):
        # give us a way to check that the context manager was called.
        from contextlib import contextmanager
        d = [0]

        @contextmanager
        def fake_restart_on_change():
            d[0] += 1
            yield

        self.patch_target('restart_on_change', new=fake_restart_on_change)
        self.patch_object(chm.charmhelpers.core.templating, 'render')
        self.patch_object(chm.os_templating,
                          'get_loader',
                          return_value='my-loader')
        # self.patch_target('adapter_instance', new='my-adapter')
        self.target.render_configs(['path1'])
        self.assertEqual(d[0], 1)
        self.render.assert_called_once_with(
            source='path1',
            template_loader='my-loader',
            target='path1',
            context=mock.ANY)
        # assert the context was an MyAdapter instance.
        context = self.render.call_args_list[0][1]['context']
        assert isinstance(context, MyAdapter)
        self.assertEqual(context.interfaces, ['interface1', 'interface2'])

    def test_render_configs_singleton_render_with_interfaces(self):
        self.patch_object(chm.charmhelpers.core.templating, 'render')
        self.patch_object(chm.os_templating,
                          'get_loader',
                          return_value='my-loader')

        self.target.singleton.render_with_interfaces(
            ['interface1', 'interface2'])
        calls = [
            mock.call(
                source='path1',
                template_loader='my-loader',
                target='path1',
                context=mock.ANY),
            mock.call(
                source='path2',
                template_loader='my-loader',
                target='path2',
                context=mock.ANY),
            mock.call(
                source='path3',
                template_loader='my-loader',
                target='path3',
                context=mock.ANY),
            mock.call(
                source='path4',
                template_loader='my-loader',
                target='path4',
                context=mock.ANY),
        ]
        self.render.assert_has_calls(calls, any_order=True)
        # Assert that None was not passed to render via the context kwarg
        for call in self.render.call_args_list:
            self.assertTrue(call[1]['context'])

    def test_assess_status_active(self):
        self.patch_object(chm.hookenv, 'status_set')
        # disable all of the check functions
        self.patch_target('check_if_paused', return_value=(None, None))
        self.patch_target('check_interfaces', return_value=(None, None))
        self.patch_target('custom_assess_status_check',
                          return_value=(None, None))
        self.patch_target('check_services_running', return_value=(None, None))
        self.target.assess_status()
        self.status_set.assert_called_once_with('active', 'Unit is ready')
        # check all the check functions got called
        self.check_if_paused.assert_called_once_with()
        self.check_interfaces.assert_called_once_with()
        self.custom_assess_status_check.assert_called_once_with()
        self.check_services_running.assert_called_once_with()

    def test_assess_status_paused(self):
        self.patch_object(chm.hookenv, 'status_set')
        # patch out _ows_check_if_paused
        self.patch_object(chm.os_utils, '_ows_check_if_paused',
                          return_value=('paused', '123'))
        self.target.assess_status()
        self.status_set.assert_called_once_with('paused', '123')
        self._ows_check_if_paused.assert_called_once_with(
            services=self.target.services,
            ports=[1, 2, 3, 1234, 2468, 3579])

    def test_states_to_check(self):
        self.patch_target('required_relations', new=['rel1', 'rel2'])
        states = self.target.states_to_check()
        self.assertEqual(
            states,
            {
                'rel1': [
                    ('rel1.connected', 'blocked', "'rel1' missing"),
                    ('rel1.available', 'waiting', "'rel1' incomplete")
                ],
                'rel2': [
                    ('rel2.connected', 'blocked', "'rel2' missing"),
                    ('rel2.available', 'waiting', "'rel2' incomplete")
                ]
            })

    def test_assess_status_check_interfaces(self):
        self.patch_object(chm.hookenv, 'status_set')
        self.patch_target('check_if_paused', return_value=(None, None))
        # first check it returns None, None if there are no states
        with mock.patch.object(self.target,
                               'states_to_check',
                               return_value={}):
            self.assertEqual(self.target.check_interfaces(), (None, None))
        # next check that we get back the states we think we should
        self.patch_object(chm.charms.reactive.bus,
                          'get_states',
                          return_value={'rel1.connected': 1, })
        self.patch_target('required_relations', new=['rel1', 'rel2'])

        def my_compare(x, y):
            if x is None:
                x = 'unknown'
            if x <= y:
                return x
            return y

        self.patch_object(chm.os_utils, 'workload_state_compare',
                          new=my_compare)
        self.assertEqual(self.target.check_interfaces(),
                         ('blocked', "'rel1' incomplete, 'rel2' missing"))
        # check that the assess_status give the same result
        self.target.assess_status()
        self.status_set.assert_called_once_with(
            'blocked', "'rel1' incomplete, 'rel2' missing")

        # Now check it returns None, None if all states are available
        self.get_states.return_value = {
            'rel1.connected': 1,
            'rel1.available': 2,
            'rel2.connected': 3,
            'rel2.available': 4,
        }
        self.assertEqual(self.target.check_interfaces(), (None, None))

    def test_check_assess_status_check_services_running(self):
        # verify that the function calls _ows_check_services_running() with the
        # valid information
        self.patch_object(chm.os_utils, '_ows_check_services_running',
                          return_value=('active', 'that'))
        status, message = self.target.check_services_running()
        self.assertEqual((status, message), ('active', 'that'))
        self._ows_check_services_running.assert_called_once_with(
            services=['my-default-service', 'my-second-service'],
            ports=[1, 2, 3, 1234, 2468, 3579])
