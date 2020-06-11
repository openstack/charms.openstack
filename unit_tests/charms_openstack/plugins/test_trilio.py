import os

from unit_tests.charms_openstack.charm.utils import BaseOpenStackCharmTest
from unit_tests.utils import patch_open

import charms_openstack.plugins.trilio as trilio


class TrilioVaultFoobar(trilio.TrilioVaultCharm):

    abstract_class = True
    name = 'test'
    all_packages = ['foo', 'bar']


class TrilioVaultFoobarSubordinate(trilio.TrilioVaultSubordinateCharm):

    abstract_class = True
    name = 'testsubordinate'
    all_packages = ['foo', 'bar', 'baz']


class TestTrilioCharmGhostAction(BaseOpenStackCharmTest):

    _nfs_shares = "10.20.30.40:/srv/trilioshare"
    _ghost_shares = "50.20.30.40:/srv/trilioshare"

    def setUp(self):
        super().setUp(trilio.TrilioVaultCharmGhostAction, {})
        self.patch_object(trilio.ch_core.hookenv, "config")
        self.patch_object(trilio.ch_core.host, "mounts")
        self.patch_object(trilio.ch_core.host, "mount")
        self.patch_object(trilio.os.path, "exists")
        self.patch_object(trilio.os, "mkdir")

        self.trilio_charm = trilio.TrilioVaultCharmGhostAction()
        self._nfs_path = os.path.join(
            trilio.TV_MOUNTS,
            self.trilio_charm._encode_endpoint(self._nfs_shares),
        )
        self._ghost_path = os.path.join(
            trilio.TV_MOUNTS,
            self.trilio_charm._encode_endpoint(self._ghost_shares),
        )

    def test_ghost_share(self):
        self.config.return_value = self._nfs_shares
        self.mounts.return_value = [
            ["/srv/nova", "/dev/sda"],
            [self._nfs_path, self._nfs_shares],
        ]
        self.exists.return_value = False
        self.trilio_charm.ghost_nfs_share(self._ghost_shares)
        self.exists.assert_called_once_with(self._ghost_path)
        self.mkdir.assert_called_once_with(self._ghost_path)
        self.mount.assert_called_once_with(
            self._nfs_path, self._ghost_path, options="bind"
        )

    def test_ghost_share_already_bound(self):
        self.config.return_value = self._nfs_shares
        self.mounts.return_value = [
            ["/srv/nova", "/dev/sda"],
            [self._nfs_path, self._nfs_shares],
            [self._ghost_path, self._nfs_shares],
        ]
        with self.assertRaises(trilio.GhostShareAlreadyMountedException):
            self.trilio_charm.ghost_nfs_share(self._ghost_shares)
        self.mount.assert_not_called()

    def test_ghost_share_nfs_unmounted(self):
        self.config.return_value = self._nfs_shares
        self.mounts.return_value = [["/srv/nova", "/dev/sda"]]
        self.exists.return_value = False
        with self.assertRaises(trilio.NFSShareNotMountedException):
            self.trilio_charm.ghost_nfs_share(self._ghost_shares)
        self.mount.assert_not_called()


class TestTrilioCommonBehaviours(BaseOpenStackCharmTest):

    def setUp(self):
        super().setUp(TrilioVaultFoobar, {})
        self.patch_object(trilio.ch_core.hookenv, "config")
        self.patch_object(trilio.ch_core.hookenv, "status_set")
        self.patch_object(trilio.fetch, "filter_installed_packages")
        self.patch_object(trilio.fetch, "apt_install")
        self.patch_object(trilio.reactive, "is_flag_set")
        self.patch_object(trilio.reactive, "clear_flag")
        self.patch_target('update_api_ports')
        self.patch_target('set_state')
        self.filter_installed_packages.side_effect = lambda p: p

    def test_install(self):
        self.is_flag_set.return_value = False

        trilio._install_triliovault(self.target)

        self.is_flag_set.assert_called_with('upgrade.triliovault')
        self.filter_installed_packages.assert_called_once_with(
            self.target.all_packages
        )
        self.apt_install.assert_called_once_with(
            self.target.all_packages,
            fatal=True
        )
        self.clear_flag.assert_not_called()
        self.set_state.assert_called_once_with('test-installed')
        self.update_api_ports.assert_called_once()

    def test_upgrade(self):
        self.is_flag_set.return_value = True

        trilio._install_triliovault(self.target)

        self.is_flag_set.assert_called_with('upgrade.triliovault')
        self.filter_installed_packages.assert_not_called()
        self.apt_install.assert_called_once_with(
            self.target.all_packages,
            fatal=True
        )
        self.clear_flag.assert_called_once_with('upgrade.triliovault')
        self.set_state.assert_called_once_with('test-installed')
        self.update_api_ports.assert_called_once()

    def test_configure_source(self):
        self.config.return_value = 'testsource'
        with patch_open() as (_open, _file):
            trilio._configure_triliovault_source()
            _open.assert_called_with(
                "/etc/apt/sources.list.d/trilio-gemfury-sources.list",
                "w"
            )
            _file.write.assert_called_once_with('testsource')


class TestTrilioVaultCharm(BaseOpenStackCharmTest):

    def setUp(self):
        super().setUp(TrilioVaultFoobar, {})
        self.patch_object(trilio, "_install_triliovault")
        self.patch_object(trilio, "_configure_triliovault_source")

    def test_series_upgrade_complete(self):
        self.patch_object(trilio.charms_openstack.charm.HAOpenStackCharm,
                          'series_upgrade_complete')
        self.patch_target('configure_source')
        self.target.series_upgrade_complete()
        self.configure_source.assert_called_once_with()

    def test_configure_source(self):
        self.patch_object(trilio.charms_openstack.charm.HAOpenStackCharm,
                          'configure_source')
        self.target.configure_source()
        self._configure_triliovault_source.assert_called_once_with()
        self.configure_source.assert_called_once_with()

    def test_install(self):
        self.patch_object(trilio.charms_openstack.charm.HAOpenStackCharm,
                          'configure_source')
        self.target.install()
        self._install_triliovault.assert_called_once_with(self.target)


class TestTrilioVaultSubordinateCharm(BaseOpenStackCharmTest):

    def setUp(self):
        super().setUp(TrilioVaultFoobarSubordinate, {})
        self.patch_object(trilio, "_install_triliovault")
        self.patch_object(trilio, "_configure_triliovault_source")

    def test_series_upgrade_complete(self):
        self.patch_object(trilio.charms_openstack.charm.OpenStackCharm,
                          'series_upgrade_complete')
        self.patch_target('configure_source')
        self.target.series_upgrade_complete()
        self.configure_source.assert_called_once_with()

    def test_configure_source(self):
        self.patch_object(trilio.charms_openstack.charm.OpenStackCharm,
                          'configure_source')
        self.target.configure_source()
        self._configure_triliovault_source.assert_called_once_with()
        self.configure_source.assert_not_called()

    def test_install(self):
        self.patch_object(trilio.charms_openstack.charm.OpenStackCharm,
                          'configure_source')
        self.target.install()
        self._install_triliovault.assert_called_once_with(self.target)
