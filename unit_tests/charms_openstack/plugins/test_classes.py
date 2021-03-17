import mock
import os
import subprocess

from unit_tests.charms_openstack.charm.utils import BaseOpenStackCharmTest

import charms_openstack.charm.classes as chm
import charms_openstack.plugins.classes as cpl


TEST_CONFIG = {'config': True,
               'openstack-origin': None}


class FakeOpenStackCephConsumingCharm(
        cpl.BaseOpenStackCephCharm,
        chm.OpenStackCharm):

    abstract_class = True


class FakeCephCharm(cpl.CephCharm):

    abstract_class = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.hostname = 'somehost'


class TestOpenStackCephConsumingCharm(BaseOpenStackCharmTest):

    def setUp(self):
        super(TestOpenStackCephConsumingCharm, self).setUp(
            FakeOpenStackCephConsumingCharm, TEST_CONFIG)

    def test_application_name(self):
        self.patch_object(cpl.ch_core.hookenv, 'application_name',
                          return_value='svc1')
        self.assertEqual(self.target.application_name, 'svc1')

    def test_ceph_service_name(self):
        self.patch_object(cpl.ch_core.hookenv, 'application_name',
                          return_value='charmname')
        self.assertEqual(
            self.target.ceph_service_name,
            'charmname')
        self.target.ceph_service_name_override = 'override'
        self.assertEqual(
            self.target.ceph_service_name,
            'override')

    def test_ceph_key_name(self):
        self.patch_object(cpl.ch_core.hookenv, 'application_name',
                          return_value='charmname')
        self.assertEqual(
            self.target.ceph_key_name,
            'client.charmname')
        self.patch_object(cpl.socket, 'gethostname', return_value='hostname')
        self.target.ceph_key_per_unit_name = True
        self.assertEqual(
            self.target.ceph_key_name,
            'client.charmname.hostname')

    def test_ceph_keyring_path(self):
        self.patch_object(cpl.ch_core.hookenv, 'application_name',
                          return_value='charmname')
        self.assertEqual(
            self.target.ceph_keyring_path,
            '/etc/ceph')
        self.target.snaps = ['gnocchi']
        self.assertEqual(
            self.target.ceph_keyring_path,
            os.path.join(cpl.SNAP_PATH_PREFIX_FORMAT.format('gnocchi'),
                         '/etc/ceph'))

    def test_configure_ceph_keyring(self):
        self.patch_object(cpl.os.path, 'isdir', return_value=False)
        self.patch_object(cpl.ch_core.host, 'mkdir')
        self.patch_object(cpl.ch_core.hookenv, 'application_name',
                          return_value='sarepta')
        self.patch_object(cpl.subprocess, 'check_call')
        self.patch_object(cpl.shutil, 'chown')
        key = 'KEY'
        self.assertEqual(self.target.configure_ceph_keyring(key),
                         '/etc/ceph/ceph.client.sarepta.keyring')
        self.isdir.assert_called_with('/etc/ceph')
        self.mkdir.assert_called_with('/etc/ceph',
                                      owner='root', group='root', perms=0o750)
        self.check_call.assert_called_with([
            'ceph-authtool',
            '/etc/ceph/ceph.client.sarepta.keyring',
            '--create-keyring', '--name=client.sarepta', '--add-key', 'KEY',
            '--mode', '0600',
        ])
        self.target.user = 'ceph'
        self.target.group = 'ceph'
        self.target.configure_ceph_keyring(key)
        self.chown.assert_called_with(
            '/etc/ceph/ceph.client.sarepta.keyring',
            user='ceph', group='ceph')

        self.patch_object(cpl.os, 'chmod')
        self.check_call.side_effect = [
            subprocess.CalledProcessError(42, [], ''), None]
        with self.assertRaises(subprocess.CalledProcessError):
            self.target.configure_ceph_keyring(key)
        self.check_call.reset_mock()
        self.check_call.side_effect = [
            subprocess.CalledProcessError(1, [], ''), None]
        self.target.configure_ceph_keyring(key)
        self.check_call.assert_has_calls([
            mock.call([
                'ceph-authtool',
                '/etc/ceph/ceph.client.sarepta.keyring',
                '--create-keyring', '--name=client.sarepta', '--add-key',
                'KEY', '--mode', '0600']),
            mock.call([
                'ceph-authtool',
                '/etc/ceph/ceph.client.sarepta.keyring',
                '--create-keyring', '--name=client.sarepta', '--add-key',
                'KEY']),
        ])
        self.chmod.assert_called_with('/etc/ceph/ceph.client.sarepta.keyring',
                                      0o600)

    def test_delete_ceph_keyring(self):
        self.patch_object(cpl.ch_core.hookenv, 'application_name',
                          return_value='sarepta')
        self.patch_object(cpl.os, 'remove')
        keyring_filename = '/etc/ceph/ceph.client.sarepta.keyring'
        self.assertEqual(self.target.delete_ceph_keyring(), keyring_filename)
        self.remove.assert_called_once_with(keyring_filename)
        self.remove.side_effect = OSError
        self.assertEqual(self.target.delete_ceph_keyring(), '')

    def test__get_bluestore_compression(self):
        self.patch_object(cpl.ch_context, 'CephBlueStoreCompressionContext')
        bluestore_compression = mock.MagicMock()
        expect = {'fake': 'value'}
        bluestore_compression.get_kwargs.return_value = expect
        self.CephBlueStoreCompressionContext.return_value = (
            bluestore_compression)
        bluestore_compression.validate.side_effect = KeyError
        self.assertEquals(self.target._get_bluestore_compression(), None)
        bluestore_compression.validate.side_effect = None
        self.assertDictEqual(
            self.target._get_bluestore_compression(),
            expect)

    def test_states_to_check(self):
        self.patch_object(chm.OpenStackCharm, 'states_to_check',
                          name='parent_states_to_check')
        expect = {'fake': [('state', 'message')]}
        self.parent_states_to_check.return_value = expect
        self.patch_target('_get_bluestore_compression')
        self.assertDictEqual(self.target.states_to_check(), expect)
        self._get_bluestore_compression.side_effect = ValueError
        result = self.target.states_to_check()
        self.assertIn('fake', result)
        self.assertIn('charm.bluestore_compression', result)

    def test_create_pool(self):
        ceph_interface = mock.MagicMock()
        self.patch_target('_get_bluestore_compression')
        self._get_bluestore_compression.side_effect = ValueError
        self.target.create_pool(ceph_interface)
        self.assertFalse(ceph_interface.create_replicated_pool.called)

        self.patch_object(cpl.ch_core.hookenv, 'application_name',
                          return_value='svc1')
        self._get_bluestore_compression.side_effect = None
        self._get_bluestore_compression.return_value = {'fake': 'value'}
        self.target.create_pool(ceph_interface)
        ceph_interface.create_replicated_pool.assert_called_once_with(
            name='svc1', fake='value')

        ceph_interface.create_replicated_pool.reset_mock()
        self.target.create_pool(ceph_interface, pool_name='custom_pool')
        ceph_interface.create_replicated_pool.assert_called_once_with(
            name='custom_pool', fake='value')


class TestCephCharm(BaseOpenStackCharmTest):

    def setUp(self):
        super(TestCephCharm, self).setUp(FakeCephCharm, {'source': None})

    def test_ceph_keyring_path(self):
        self.patch_object(cpl.ch_core.hookenv, 'application_name',
                          return_value='charmname')
        self.assertEqual(
            self.target.ceph_keyring_path,
            '/var/lib/ceph/charmname')
        self.target.snaps = ['gnocchi']
        self.assertEqual(
            self.target.ceph_keyring_path,
            os.path.join(cpl.SNAP_PATH_PREFIX_FORMAT.format('gnocchi'),
                         '/var/lib/ceph/charmname'))
        self.target.snaps = []
        self.target.ceph_service_type = self.target.CephServiceType.mds
        self.assertEqual(
            self.target.ceph_keyring_path,
            '/var/lib/ceph/charmname/ceph-somehost')
        self.target.snaps = ['somecephsnap']
        self.assertEqual(
            self.target.ceph_keyring_path,
            os.path.join(cpl.SNAP_PATH_PREFIX_FORMAT.format('gnocchi'),
                         '/var/lib/ceph/charmname/ceph-somehost'))

    def test_configure_ceph_keyring(self):
        self.patch_object(cpl.os.path, 'isdir', return_value=False)
        self.patch_object(cpl.ch_core.host, 'mkdir')
        self.patch_object(cpl.ch_core.hookenv, 'application_name',
                          return_value='sarepta')
        self.patch_object(cpl.subprocess, 'check_call')
        self.patch_object(cpl.shutil, 'chown')
        self.patch_object(cpl.os, 'symlink')
        key = 'KEY'
        self.patch_object(cpl.os.path, 'exists', return_value=True)
        self.patch_object(cpl.os, 'readlink')
        self.patch_object(cpl.os, 'remove')
        self.readlink.side_effect = OSError
        self.target.ceph_service_type = self.target.CephServiceType.mds
        self.target.configure_ceph_keyring(key)
        self.isdir.assert_called_with('/var/lib/ceph/sarepta/ceph-somehost')
        self.mkdir.assert_called_with('/var/lib/ceph/sarepta/ceph-somehost',
                                      owner='root', group='root', perms=0o750)
        self.check_call.assert_called_with([
            'ceph-authtool',
            '/var/lib/ceph/sarepta/ceph-somehost/keyring',
            '--create-keyring', '--name=sarepta', '--add-key', 'KEY',
            '--mode', '0600',
        ])
        self.exists.assert_not_called()
        self.readlink.assert_not_called()
        self.symlink.assert_not_called()
        self.target.ceph_service_type = self.target.CephServiceType.client
        self.target.configure_ceph_keyring(key)
        self.isdir.assert_called_with('/var/lib/ceph/sarepta')
        self.mkdir.assert_called_with('/var/lib/ceph/sarepta',
                                      owner='root', group='root', perms=0o750)
        self.check_call.assert_called_with([
            'ceph-authtool',
            '/var/lib/ceph/sarepta/ceph.client.sarepta.keyring',
            '--create-keyring', '--name=client.sarepta', '--add-key', 'KEY',
            '--mode', '0600',
        ])
        self.exists.assert_called_with(
            '/etc/ceph/ceph.client.sarepta.keyring')
        self.readlink.assert_called_with(
            '/etc/ceph/ceph.client.sarepta.keyring')
        assert not self.remove.called
        self.symlink.assert_called_with(
            '/var/lib/ceph/sarepta/ceph.client.sarepta.keyring',
            '/etc/ceph/ceph.client.sarepta.keyring')
        self.readlink.side_effect = None
        self.readlink.return_value = '/some/where/else'
        self.target.configure_ceph_keyring(key)
        self.remove.assert_called_with('/etc/ceph/ceph.client.sarepta.keyring')

    def test_delete_ceph_keyring(self):
        self.patch_object(cpl.ch_core.hookenv, 'application_name',
                          return_value='sarepta')
        self.patch_object(cpl.os, 'remove')
        self.target.delete_ceph_keyring()
        self.remove.assert_called_once_with(
            '/var/lib/ceph/sarepta/ceph.client.sarepta.keyring')
        self.remove.reset_mock()
        self.target.ceph_service_type = self.target.CephServiceType.mds
        self.target.delete_ceph_keyring()
        self.remove.assert_called_once_with(
            '/var/lib/ceph/sarepta/ceph-somehost/keyring')

    def test_install(self):
        self.patch_object(cpl.subprocess, 'check_output', return_value=b'\n')
        self.patch_target('configure_source')
        self.target.install()
        self.target.configure_source.assert_called()
        self.check_output.assert_called()


class MockCharmForPolicydOverrid(object):

    def __init__(self, *args, **kwargs):
        self._restart_services = False
        self._install = False
        self._upgrade_charm = False
        self._config_changed = False
        self.release = 'mitaka'
        self.policyd_service_name = 'aservice'
        super().__init__(*args, **kwargs)

    def restart_services(self):
        self._restart_services = True

    def install(self):
        self._install = True

    def upgrade_charm(self):
        self._upgrade_charm = True

    def config_changed(self):
        self._config_changed = True


class FakeConsumingPolicydOverride(cpl.PolicydOverridePlugin,
                                   MockCharmForPolicydOverrid):

    pass


class TestPolicydOverridePlugin(BaseOpenStackCharmTest):

    def setUp(self):
        super(TestPolicydOverridePlugin, self).setUp(
            FakeConsumingPolicydOverride, TEST_CONFIG)

    def test__policyd_function_args_no_defines(self):
        args, kwargs = self.target._policyd_function_args()
        self.assertEqual(args, ['mitaka', 'aservice'])
        self.assertEqual(kwargs, {
            'blacklist_paths': None,
            'blacklist_keys': None,
            'template_function': None,
            'restart_handler': None
        })

    def test__policyd_function_args_with_defines(self):
        def my_template_fn(s):
            return "done"

        self.target.policyd_blacklist_paths = ['p1']
        self.target.policyd_blacklist_keys = ['k1']
        self.target.policyd_template_function = my_template_fn
        self.target.policyd_restart_on_change = True
        args, kwargs = self.target._policyd_function_args()
        self.assertEqual(args, ['mitaka', 'aservice'])
        self.assertEqual(kwargs, {
            'blacklist_paths': ['p1'],
            'blacklist_keys': ['k1'],
            'template_function': my_template_fn,
            'restart_handler': self.target.restart_services
        })

    def test__maybe_policyd_overrides(self):
        self.patch_target('_policyd_function_args',
                          return_value=(["args"], {"kwargs": 1}))
        self.patch_object(cpl.ch_policyd,
                          'maybe_do_policyd_overrides',
                          name='mock_policyd_call')
        self.target._maybe_policyd_overrides()
        self.mock_policyd_call.assert_called_once_with(
            "args", kwargs=1)

    def test_install_calls_policyd(self):
        self.patch_target('_maybe_policyd_overrides')
        self.target.install()
        self.assertTrue(self.target._install)
        self._maybe_policyd_overrides.assert_called_once_with()

    def test_upgrade_charm_calls_policyd(self):
        self.patch_target('_maybe_policyd_overrides')
        self.target.upgrade_charm()
        self.assertTrue(self.target._upgrade_charm)
        self._maybe_policyd_overrides.assert_called_once_with()

    def test_config_changed_calls_into_policyd_library(self):
        self.patch_target('_policyd_function_args',
                          return_value=(["args"], {"kwargs": 1}))
        self.patch_object(cpl.ch_policyd,
                          'maybe_do_policyd_overrides_on_config_changed',
                          name='mock_policyd_call')
        self.target.config_changed()
        self.assertTrue(self.target._config_changed)
        self._policyd_function_args.assert_called_once_with()
        self.mock_policyd_call.assert_called_once_with(
            "args", kwargs=1)
