import mock
import os
import subprocess

from unit_tests.charms_openstack.charm.utils import BaseOpenStackCharmTest

import charms_openstack.charm.classes as chm
import charms_openstack.plugins.classes as cpl

TEST_CONFIG = {'config': True,
               'openstack-origin': None}


class FakeOpenStackCephConsumingCharm(
        chm.OpenStackCharm,
        cpl.BaseOpenStackCephCharm):
    abstract_class = True


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


class TestCephCharm(BaseOpenStackCharmTest):

    def setUp(self):
        super(TestCephCharm, self).setUp(cpl.CephCharm, {'source': None})

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

    def test_install(self):
        self.patch_object(cpl.subprocess, 'check_output', return_value=b'\n')
        self.patch_target('configure_source')
        self.target.install()
        self.target.configure_source.assert_called()
        self.check_output.assert_called()
