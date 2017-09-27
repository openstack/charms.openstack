import base64
import mock

import unit_tests.utils as utils
from unit_tests.charms_openstack.charm.utils import BaseOpenStackCharmTest
from unit_tests.charms_openstack.charm.common import MyOpenStackCharm

import charms_openstack.charm.classes as chm
import charms_openstack.charm.core as chm_core

TEST_CONFIG = {'config': True,
               'openstack-origin': None}


class TestOpenStackCharm__init__(BaseOpenStackCharmTest):
    # Just test the __init__() function, as it takes some params which do some
    # initalisation.

    def setUp(self):

        class NoOp(object):
            pass

        # bypass setting p the charm directly, as we want control over that.
        super(TestOpenStackCharm__init__, self).setUp(NoOp, TEST_CONFIG)

    def test_empty_init_args(self):
        target = chm.OpenStackCharm()
        self.assertIsNone(target.release)
        # we expect target.adapters_instance to not be None as
        # target.adapters_class is not None as a default
        self.assertIsNotNone(target.adapters_instance)
        # from mocked hookenv.config()
        self.assertEqual(target.config, TEST_CONFIG)

    def test_filled_init_args(self):
        self.patch_object(chm_core, '_releases', new={})

        class TestCharm(chm.OpenStackCharm):
            release = 'mitaka'
            adapters_class = mock.MagicMock()

        target = TestCharm('interfaces', 'config', 'release')
        self.assertEqual(target.release, 'release')
        self.assertEqual(target.config, 'config')
        self.assertIsInstance(target.adapters_instance, mock.MagicMock)
        TestCharm.adapters_class.assert_called_once_with(
            'interfaces', charm_instance=target)


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
        self.patch_object(chm_core.charmhelpers.fetch,
                          'filter_installed_packages',
                          name='fip',
                          return_value=None)
        self.patch_object(chm.subprocess, 'check_output', return_value=b'\n')
        self.target.install()
        self.target.set_state.assert_called_once_with('charmname-installed')
        self.fip.assert_called_once_with([])

    def test_all_packages(self):
        self.assertEqual(self.target.packages, self.target.all_packages)

    def test_full_restart_map(self):
        self.assertEqual(self.target.full_restart_map, self.target.restart_map)

    def test_set_state(self):
        # tests that OpenStackCharm.set_state() calls set_state() global
        self.patch_object(chm.reactive.bus, 'set_state')
        self.target.set_state('hello')
        self.set_state.assert_called_once_with('hello', None)
        self.set_state.reset_mock()
        self.target.set_state('hello', 'there')
        self.set_state.assert_called_once_with('hello', 'there')

    def test_remove_state(self):
        # tests that OpenStackCharm.remove_state() calls remove_state() global
        self.patch_object(chm.reactive.bus, 'remove_state')
        self.target.remove_state('hello')
        self.remove_state.assert_called_once_with('hello')

    def test_configure_source(self):
        self.patch_object(chm.os_utils,
                          'configure_installation_source',
                          name='cis')
        self.patch_object(chm_core.charmhelpers.fetch, 'apt_update')
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
        self.patch_object(chm_core, 'subprocess', name='subprocess')
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


class TestMyOpenStackCharm(BaseOpenStackCharmTest):

    def setUp(self):
        def make_open_stack_charm():
            return MyOpenStackCharm(['interface1', 'interface2'])

        super(TestMyOpenStackCharm, self).setUp(make_open_stack_charm,
                                                TEST_CONFIG)

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

    def test_application_version_unspecified(self):
        self.patch_object(chm.os_utils, 'os_release')
        self.patch_object(chm, 'get_upstream_version',
                          return_value='1.2.3')
        self.patch_object(chm.os_utils, 'snap_install_requested',
                          return_value=False)
        self.target.version_package = None
        self.assertEqual(self.target.application_version, '1.2.3')
        self.get_upstream_version.assert_called_once_with('p1')

    def test_application_version_package(self):
        self.patch_object(chm.os_utils, 'os_release')
        self.patch_object(chm, 'get_upstream_version',
                          return_value='1.2.3')
        self.patch_object(chm.os_utils, 'snap_install_requested',
                          return_value=False)
        self.assertEqual(self.target.application_version, '1.2.3')
        self.get_upstream_version.assert_called_once_with('p2')

    def test_application_version_snap(self):
        self.patch_object(chm, 'get_snap_version',
                          return_value='4.0.3')
        self.patch_object(chm.os_utils, 'snap_install_requested',
                          return_value=True)
        self.assertEqual(self.target.application_version, '4.0.3')
        self.get_snap_version.assert_called_once_with('mysnap', fatal=False)

    def test_application_version_dfs(self):
        self.patch_object(chm.os_utils, 'os_release',
                          return_value='mitaka')
        self.patch_object(chm, 'get_upstream_version',
                          return_value=None)
        self.patch_object(chm.os_utils, 'snap_install_requested',
                          return_value=False)
        self.assertEqual(self.target.application_version, 'mitaka')
        self.get_upstream_version.assert_called_once_with('p2')
        self.os_release.assert_called_once_with('p2')


class TestOpenStackAPICharm(BaseOpenStackCharmTest):

    def setUp(self):
        super(TestOpenStackAPICharm, self).setUp(chm.OpenStackAPICharm,
                                                 TEST_CONFIG)

    def test_upgrade_charm(self):
        self.patch_target('setup_token_cache')
        self.patch_target('update_api_ports')
        self.target.upgrade_charm()
        self.target.setup_token_cache.assert_called_once_with()

    def test_install(self):
        # Test set_state and configure_source are called
        self.patch_target('set_state')
        self.patch_target('configure_source')
        self.patch_target('enable_memcache', return_value=False)
        self.patch_object(chm_core.charmhelpers.fetch,
                          'filter_installed_packages',
                          name='fip',
                          return_value=None)
        self.patch_object(chm.subprocess, 'check_output', return_value=b'\n')
        self.target.install()
        # self.target.set_state.assert_called_once_with('charmname-installed')
        self.target.configure_source.assert_called_once_with()
        self.fip.assert_called_once_with([])

    def test_setup_token_cache(self):
        self.patch_target('token_cache_pkgs')
        self.patch_target('install')
        self.patch_object(chm_core.charmhelpers.fetch,
                          'filter_installed_packages',
                          name='fip',
                          return_value=['memcached'])
        self.target.setup_token_cache()
        self.install.assert_called_once_with()
        self.fip.return_value = []
        self.install.reset_mock()
        self.target.setup_token_cache()
        self.assertFalse(self.install.called)

    def test_enable_memcache(self):
        self.assertFalse(self.target.enable_memcache(release='liberty'))
        self.assertTrue(self.target.enable_memcache(release='newton'))
        self.patch_target('config', new={'openstack-origin': 'distro'})
        self.patch_object(chm.os_utils,
                          'get_os_codename_install_source',
                          name='gocis')
        self.gocis.return_value = 'liberty'
        self.assertFalse(self.target.enable_memcache())
        self.gocis.return_value = 'newton'
        self.assertTrue(self.target.enable_memcache())

    def test_token_cache_pkgs(self):
        self.patch_target('enable_memcache')
        self.enable_memcache.return_value = True
        self.assertEqual(self.target.token_cache_pkgs(), ['memcached',
                                                          'python-memcache'])
        self.enable_memcache.return_value = False
        self.assertEqual(self.target.token_cache_pkgs(), [])

    def test_get_amqp_credentials(self):
        # verify that the instance throws an error if not overriden
        with self.assertRaises(RuntimeError):
            self.target.get_amqp_credentials()

    def test_get_database_setup(self):
        # verify that the instance throws an error if not overriden
        with self.assertRaises(RuntimeError):
            self.target.get_database_setup()

    def test_all_packages(self):
        self.patch_target('enable_memcache')
        self.patch_target('packages', new=['pkg1', 'pkg2'])
        self.enable_memcache.return_value = True
        self.assertEqual(self.target.all_packages,
                         ['pkg1', 'pkg2', 'memcached', 'python-memcache'])
        self.enable_memcache.return_value = False
        self.assertEqual(self.target.all_packages, ['pkg1', 'pkg2'])

    def test_full_restart_map(self):
        self.patch_target('enable_memcache')
        base_restart_map = {
            'conf1': ['svc1'],
            'conf2': ['svc1']}
        self.patch_target('restart_map', new=base_restart_map)
        self.enable_memcache.return_value = True
        self.assertEqual(self.target.full_restart_map,
                         {'conf1': ['svc1'],
                          'conf2': ['svc1'],
                          '/etc/memcached.conf': ['memcached']})
        self.enable_memcache.return_value = False
        self.assertEqual(self.target.full_restart_map, base_restart_map)


class TestHAOpenStackCharm(BaseOpenStackCharmTest):
    # Note that this only tests the OpenStackCharm() class, which has not very
    # useful defaults for testing.  In order to test all the code without too
    # many mocks, a separate test dervied charm class is used below.

    def setUp(self):
        super(TestHAOpenStackCharm, self).setUp(chm.HAOpenStackCharm,
                                                TEST_CONFIG)

    def test_all_packages(self):
        self.patch_target('packages', new=['pkg1'])
        self.patch_target('token_cache_pkgs', return_value=[])
        self.patch_target('haproxy_enabled', return_value=False)
        self.patch_target('apache_enabled', return_value=False)
        self.patch_object(chm.os_utils, 'snap_install_requested',
                          return_value=False)
        self.assertEqual(['pkg1'], self.target.all_packages)
        self.token_cache_pkgs.return_value = ['memcache']
        self.haproxy_enabled.return_value = True
        self.apache_enabled.return_value = True
        self.assertEqual(['pkg1', 'memcache', 'haproxy', 'apache2'],
                         self.target.all_packages)

    def test_full_restart_map_disabled(self):
        base_restart_map = {
            'conf1': ['svc1'],
            'conf2': ['svc1']}
        self.patch_target('restart_map', new=base_restart_map)
        self.patch_target('enable_memcache', return_value=False)
        self.patch_target('haproxy_enabled', return_value=False)
        self.patch_target('apache_enabled', return_value=False)
        self.assertEqual(base_restart_map, self.target.full_restart_map)

    def test_full_restart_map_enabled(self):
        base_restart_map = {
            'conf1': ['svc1'],
            'conf2': ['svc1']}
        self.patch_target('restart_map', new=base_restart_map)
        self.patch_target('enable_memcache', return_value=True)
        self.patch_target('haproxy_enabled', return_value=True)
        self.patch_target('apache_enabled', return_value=True)
        self.patch_object(chm.os_utils, 'snap_install_requested',
                          return_value=False)
        self.assertEqual(
            self.target.full_restart_map,
            {'/etc/apache2/sites-available/openstack_https_frontend.conf':
             ['apache2'],
             '/etc/haproxy/haproxy.cfg': ['haproxy'],
             '/etc/memcached.conf': ['memcached'],
             'conf1': ['svc1'],
             'conf2': ['svc1']})

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
        self.patch_object(chm.reactive.bus, 'get_state')
        self.patch_object(chm.reactive.bus, 'set_state')
        self.get_state.return_value = None
        self.target.set_haproxy_stat_password()
        self.set_state.assert_called_once_with('haproxy.stat.password',
                                               mock.ANY)

    def test_hacharm_all_packages_enabled(self):
        self.patch_target('enable_memcache', return_value=False)
        self.patch_target('haproxy_enabled', return_value=True)
        self.assertTrue('haproxy' in self.target.all_packages)

    def test_hacharm_all_packages_disabled(self):
        self.patch_target('enable_memcache', return_value=False)
        self.patch_target('haproxy_enabled', return_value=False)
        self.assertFalse('haproxy' in self.target.all_packages)

    def test_hacharm_full_restart_map(self):
        self.patch_target('enable_memcache', return_value=False)
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
        self.patch_object(chm.os_utils, 'snap_install_requested',
                          return_value=False)
        self.target.enable_apache_modules()
        self.check_call.assert_called_once_with(
            ['a2enmod', 'proxy_http'])
        self.service_restart.assert_called_once_with('apache2')

    def test_configure_cert(self):
        self.patch_object(chm.ch_host, 'mkdir')
        self.patch_object(chm.ch_host, 'write_file')
        self.patch_object(chm.os_utils, 'snap_install_requested',
                          return_value=False)
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
        config = {
            'ssl_key': base64.b64encode(b'key'),
            'ssl_cert': base64.b64encode(b'cert'),
            'ssl_ca': base64.b64encode(b'ca')}
        self.patch_target('config', new=config)
        self.patch_object(chm.os_utils, 'snap_install_requested',
                          return_value=False)
        self.assertEqual(
            self.target.get_certs_and_keys(),
            [{'key': 'key', 'cert': 'cert', 'ca': 'ca', 'cn': None}])

    def test_get_certs_and_keys_noca(self):
        config = {
            'ssl_key': base64.b64encode(b'key'),
            'ssl_cert': base64.b64encode(b'cert')}
        self.patch_target('config', new=config)
        self.patch_object(chm.os_utils, 'snap_install_requested',
                          return_value=False)
        self.assertEqual(
            self.target.get_certs_and_keys(),
            [{'key': 'key', 'cert': 'cert', 'ca': None, 'cn': None}])

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
        self.patch_object(chm.os_utils, 'snap_install_requested',
                          return_value=False)
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

    def test_config_defined_certs_and_keys(self):
        # test that the cached parameters do what we expect
        config = {
            'ssl_key': base64.b64encode(b'confkey'),
            'ssl_cert': base64.b64encode(b'confcert'),
            'ssl_ca': base64.b64encode(b'confca')}
        self.patch_target('config', new=config)
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
        self.patch_object(chm.reactive.bus, 'set_state')
        self.patch_object(chm.reactive.RelationBase, 'from_state',
                          return_value=None)
        self.patch_object(chm_core.charmhelpers.fetch,
                          'filter_installed_packages',
                          name='fip',
                          return_value=['apache2'])
        self.patch_object(chm_core.charmhelpers.fetch,
                          'apt_install',
                          name='apt_install')
        self.patch_object(chm.os_utils, 'snap_install_requested',
                          return_value=False)
        self.target.configure_ssl()
        cert_calls = [
            mock.call('cert1', 'key1', cn='cn1'),
            mock.call('cert2', 'key2', cn='cn2')]
        ca_calls = [
            mock.call('ca1'),
            mock.call('ca2')]
        set_state_calls = [
            mock.call('ssl.requested', True),
            mock.call('ssl.enabled', True)]
        self.configure_cert.assert_has_calls(cert_calls)
        self.configure_ca.assert_has_calls(ca_calls)
        self.configure_apache.assert_called_once_with()
        self.set_state.assert_has_calls(set_state_calls)

    def test_configure_ssl_off(self):
        self.patch_target('get_certs_and_keys', return_value=[])
        self.patch_object(chm.reactive.bus, 'set_state')
        self.patch_object(chm.reactive.RelationBase, 'from_state',
                          return_value=None)
        self.patch_object(chm.os_utils, 'snap_install_requested',
                          return_value=False)
        self.target.configure_ssl()
        self.set_state.assert_called_once_with('ssl.enabled', False)

    def test_configure_ssl_rabbit(self):
        self.patch_target('get_certs_and_keys', return_value=[])
        self.patch_target('configure_rabbit_cert')
        self.patch_object(chm.reactive.bus, 'set_state')
        self.patch_object(chm.reactive.RelationBase, 'from_state',
                          return_value='ssl_int')
        self.patch_object(chm.os_utils, 'snap_install_requested',
                          return_value=False)
        self.target.configure_ssl()
        self.set_state.assert_called_once_with('ssl.enabled', False)
        self.configure_rabbit_cert.assert_called_once_with('ssl_int')

    def test_configure_rabbit_cert(self):
        rabbit_int_mock = mock.MagicMock()
        rabbit_int_mock.get_ssl_cert.return_value = 'rabbit_cert'
        self.patch_object(chm.os.path, 'exists', return_value=True)
        self.patch_object(chm.os, 'mkdir')
        self.patch_object(chm.hookenv, 'service_name', return_value='svc1')
        with utils.patch_open() as (mock_open, mock_file):
            self.target.configure_rabbit_cert(rabbit_int_mock)
            mock_open.assert_called_with(
                '/var/lib/charm/svc1/rabbit-client-ca.pem',
                'w')
            mock_file.write.assert_called_with('rabbit_cert')

    def test_configure_ca(self):
        self.patch_target('run_update_certs')
        with utils.patch_open() as (mock_open, mock_file):
            self.target.configure_ca('myca')
            mock_open.assert_called_with(
                '/usr/local/share/ca-certificates/keystone_juju_ca_cert.crt',
                'w')
            mock_file.write.assert_called_with('myca')

    def test_run_update_certs(self):
        self.patch_object(chm.subprocess, 'check_call')
        self.target.run_update_certs()
        self.check_call.assert_called_once_with(
            ['update-ca-certificates', '--fresh'])

    def test_update_central_cacerts(self):
        self.patch_target('run_update_certs')
        change_hashes = ['hash1', 'hash2']
        nochange_hashes = ['hash1', 'hash1']

        def fake_hash(hash_dict):
            def fake_hash_inner(filename):
                return hash_dict.pop()
            return fake_hash_inner
        self.patch_object(chm.ch_host, 'path_hash')
        self.path_hash.side_effect = fake_hash(change_hashes)
        with self.target.update_central_cacerts(['file1']):
            pass
        self.run_update_certs.assert_called_with()
        self.run_update_certs.reset_mock()
        self.path_hash.side_effect = fake_hash(nochange_hashes)
        with self.target.update_central_cacerts(['file1']):
            pass
        self.assertFalse(self.run_update_certs.called)
