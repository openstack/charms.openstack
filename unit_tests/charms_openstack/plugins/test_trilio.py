import unittest.mock as mock
import os

from unit_tests.charms_openstack.charm.utils import BaseOpenStackCharmTest
from unit_tests.utils import BaseTestCase, patch_open

import charms_openstack.charm.core as co_core
import charms_openstack.plugins.trilio as trilio


class TrilioVaultFoobar(trilio.TrilioVaultCharm):

    abstract_class = True
    name = 'test'
    all_packages = ['foo', 'bar']
    os_release_pkg = 'nova-common'

    @classmethod
    def trilio_version_package(cls):
        return "dmapi"


class TrilioVaultFoobarSubordinate(trilio.TrilioVaultSubordinateCharm):

    abstract_class = True
    name = 'testsubordinate'
    all_packages = ['foo', 'bar', 'baz']


class TestTrilioCharmGhostAction(BaseOpenStackCharmTest):

    _nfs_share = "10.20.30.40:/srv/trilioshare"
    _ghost_share = "50.20.30.40:/srv/trilioghostshare"

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
            self.trilio_charm._encode_endpoint(self._nfs_share),
        )
        self._ghost_path = os.path.join(
            trilio.TV_MOUNTS,
            self.trilio_charm._encode_endpoint(self._ghost_share),
        )

    def test__ghost_nfs_share(self):
        self.config.return_value = self._nfs_share
        self.mounts.return_value = [
            ["/srv/nova", "/dev/sda"],
            [self._nfs_path, self._nfs_share],
        ]
        self.exists.return_value = False
        self.trilio_charm._ghost_nfs_share(self._nfs_share,
                                           self._ghost_share)
        self.exists.assert_called_once_with(self._ghost_path)
        self.mkdir.assert_called_once_with(self._ghost_path)
        self.mount.assert_called_once_with(
            self._nfs_path, self._ghost_path, options="bind"
        )

    def test__ghost_nfs_share_already_bound(self):
        self.config.return_value = self._nfs_share
        self.mounts.return_value = [
            ["/srv/nova", "/dev/sda"],
            [self._nfs_path, self._nfs_share],
            [self._ghost_path, self._nfs_share],
        ]
        with self.assertRaises(trilio.GhostShareAlreadyMountedException):
            self.trilio_charm._ghost_nfs_share(self._nfs_share,
                                               self._ghost_share)
        self.mount.assert_not_called()

    def test__ghost_nfs_share_nfs_unmounted(self):
        self.config.return_value = self._nfs_share
        self.mounts.return_value = [["/srv/nova", "/dev/sda"]]
        self.exists.return_value = False
        with self.assertRaises(trilio.NFSShareNotMountedException):
            self.trilio_charm._ghost_nfs_share(self._nfs_share,
                                               self._ghost_share)
        self.mount.assert_not_called()

    def test_ghost_nfs_share(self):
        self.patch_object(self.trilio_charm, "_ghost_nfs_share")
        self.config.return_value = (
            "10.20.30.40:/srv/trilioshare,10.20.30.40:/srv/trilioshare2"
        )
        self.trilio_charm.ghost_nfs_share(
            "50.20.30.40:/srv/trilioshare,50.20.30.40:/srv/trilioshare2"
        )
        self._ghost_nfs_share.assert_has_calls([
            mock.call("10.20.30.40:/srv/trilioshare",
                      "50.20.30.40:/srv/trilioshare"),
            mock.call("10.20.30.40:/srv/trilioshare2",
                      "50.20.30.40:/srv/trilioshare2")
        ])

    def test_ghost_nfs_share_mismatch(self):
        self.patch_object(self.trilio_charm, "_ghost_nfs_share")
        self.config.return_value = (
            "10.20.30.40:/srv/trilioshare,10.20.30.40:/srv/trilioshare2"
        )
        with self.assertRaises(trilio.MismatchedConfigurationException):
            self.trilio_charm.ghost_nfs_share(
                "50.20.30.40:/srv/trilioshare"
            )


class TestTrilioVault42CharmGhostAction(BaseOpenStackCharmTest):

    _nfs_share = "10.20.30.40:/srv/trilioshare"
    _ghost_share = "50.20.30.40:/srv/trilioghostshare"

    def setUp(self):
        super().setUp(trilio.TrilioVaultCharmGhostAction, {})
        self.patch_object(trilio.ch_core.hookenv, "config")
        self.patch_object(trilio.ch_core.host, "mounts")
        self.patch_object(trilio.ch_core.host, "mount")
        self.patch_object(trilio.os.path, "exists")
        self.patch_object(trilio.os, "mkdir")

        self.trilio_charm = trilio.TrilioVault42CharmGhostAction()
        self._nfs_path = os.path.join(
            trilio.TV_MOUNTS,
            self.trilio_charm._encode_endpoint(self._nfs_share),
        )
        self._ghost_path = os.path.join(
            trilio.TV_MOUNTS,
            self.trilio_charm._encode_endpoint(self._ghost_share),
        )

    def test__ghost_nfs_share(self):
        self.config.return_value = self._nfs_share
        self.mounts.return_value = [
            ["/srv/nova", "/dev/sda"],
            [self._nfs_path, self._nfs_share],
        ]
        self.exists.return_value = False
        self.trilio_charm._ghost_nfs_share(self._nfs_share,
                                           self._ghost_share)
        self.exists.assert_called_once_with(self._ghost_path)
        self.mkdir.assert_called_once_with(self._ghost_path)
        self.mount.assert_called_once_with(
            self._nfs_path, self._ghost_path, options="bind"
        )

    def test__ghost_nfs_share_already_bound(self):
        self.config.return_value = self._nfs_share
        self.mounts.return_value = [
            ["/srv/nova", "/dev/sda"],
            [self._nfs_path, self._nfs_share],
            [self._ghost_path, self._nfs_share],
        ]
        with self.assertRaises(trilio.GhostShareAlreadyMountedException):
            self.trilio_charm._ghost_nfs_share(self._nfs_share,
                                               self._ghost_share)
        self.mount.assert_not_called()

    def test__ghost_nfs_share_nfs_unmounted(self):
        self.config.return_value = self._nfs_share
        self.mounts.return_value = [["/srv/nova", "/dev/sda"]]
        self.exists.return_value = False
        with self.assertRaises(trilio.NFSShareNotMountedException):
            self.trilio_charm._ghost_nfs_share(self._nfs_share,
                                               self._ghost_share)
        self.mount.assert_not_called()

    def test_ghost_nfs_share(self):
        self.patch_object(self.trilio_charm, "_ghost_nfs_share")
        self.config.return_value = (
            "10.20.30.40:/srv/trilioshare,10.20.30.40:/srv/trilioshare2"
        )
        self.trilio_charm.ghost_nfs_share(
            "50.20.30.40:/srv/trilioshare,50.20.30.40:/srv/trilioshare2"
        )
        self._ghost_nfs_share.assert_has_calls([
            mock.call("10.20.30.40:/srv/trilioshare",
                      "50.20.30.40:/srv/trilioshare"),
            mock.call("10.20.30.40:/srv/trilioshare2",
                      "50.20.30.40:/srv/trilioshare2")
        ])

    def test_ghost_nfs_share_mismatch(self):
        self.patch_object(self.trilio_charm, "_ghost_nfs_share")
        self.config.return_value = (
            "10.20.30.40:/srv/trilioshare,10.20.30.40:/srv/trilioshare2"
        )
        with self.assertRaises(trilio.MismatchedConfigurationException):
            self.trilio_charm.ghost_nfs_share(
                "50.20.30.40:/srv/trilioshare"
            )


class TestTrilioCommonBehaviours(BaseOpenStackCharmTest):

    def setUp(self):
        super().setUp(TrilioVaultFoobar, {})
        self.patch_object(trilio.ch_core.hookenv, "config")
        self.patch_object(trilio.ch_core.hookenv, "status_set")
        self.patch_object(trilio.fetch, "filter_installed_packages")
        self.patch_object(trilio.fetch, "apt_install")
        self.patch_object(trilio.fetch.apt_pkg, 'version_compare')
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

    def test_trilio_properties(self):
        cls_mock = mock.MagicMock()
        cls_mock.charm_instance.release_pkg_version = lambda: '4.0'
        self.version_compare.return_value = 0
        self.assertEqual(
            trilio.trilio_properties(cls_mock),
            {'db_type': 'dedicated', 'transport_type': 'dmapi'})
        self.version_compare.return_value = -1
        self.assertEqual(
            trilio.trilio_properties(cls_mock),
            {'db_type': 'legacy', 'transport_type': 'legacy'})

    def test_trilio_s3_cert_config(self):
        cls_mock = mock.MagicMock()
        self.config.return_value = 'QSBjZXJ0Cg=='
        self.assertEqual(
            trilio.trilio_s3_cert_config(cls_mock),
            {
                'cert_file': '/usr/share/ca-certificates/charm-s3.cert',
                'cert_data': 'A cert\n'})
        self.config.return_value = None
        self.assertEqual(
            trilio.trilio_s3_cert_config(cls_mock),
            {})

    def test_get_trilio_codename_install_source(self):
        self.assertEqual(
            trilio.get_trilio_codename_install_source(
                'deb [trusted=yes] https://apt.fury.io/triliodata-4-0/ /'),
            '4.0')
        self.assertEqual(
            trilio.get_trilio_codename_install_source(
                'deb [trusted=yes] https://apt.fury.io/triliodata-4-0-0/ /'),
            '4.0')
        with self.assertRaises(AssertionError):
            trilio.get_trilio_codename_install_source(
                'deb [trusted=yes] https://apt.fury.io/triliodata/ /')

    def test_get_trilio_charm_instance(self):
        _safe_gcif = co_core._get_charm_instance_function
        co_core._get_charm_instance_function = None

        class BaseClass():
            def __init__(self, release, *args, **kwargs):
                pass

        class Pike39(BaseClass):
            release = 'pike'
            trilio_release = '3.9'

        class Queens40(BaseClass):
            release = 'queens'
            trilio_release = '4.0'

        class Queens41(BaseClass):
            release = 'queens'
            trilio_release = '4.1'

        class Rocky40(BaseClass):
            release = 'rocky'
            trilio_release = '4.0'

        def _version_compare(ver1, ver2):
            if float(ver1) > float(ver2):
                return 1
            elif float(ver1) < float(ver2):
                return -1
            else:
                return 0

        save_releases = trilio._trilio_releases
        self.version_compare.side_effect = _version_compare
        trilio._trilio_releases = {
            'pike': {
                trilio.AptPkgVersion('3.9'): {
                    'deb': Pike39}},
            'queens': {
                trilio.AptPkgVersion('4.0'): {
                    'deb': Queens40},
                trilio.AptPkgVersion('4.1'): {
                    'deb': Queens41}},
            'rocky': {
                trilio.AptPkgVersion('4.0'): {
                    'deb': Rocky40}}}
        trilio.make_trilio_get_charm_instance_handler()
        # Check with no release being supplied. Should return the
        # highest release class.
        self.assertIsInstance(
            co_core.get_charm_instance(),
            Rocky40)
        self.assertIsInstance(
            co_core.get_charm_instance(release='queens_4.0'),
            Queens40)
        self.assertIsInstance(
            co_core.get_charm_instance(release='queens_4.1'),
            Queens41)
        # Ensure an error is raised if a class satisfying the trilio condition
        # is not found for the highest matching OpenStack class.
        with self.assertRaises(RuntimeError):
            co_core.get_charm_instance(release='rocky_3.9')
        # Match the openstack release and then the closest trilio releases
        # within that subset.
        self.assertIsInstance(
            co_core.get_charm_instance(release='rocky_4.1'),
            Rocky40)
        with self.assertRaises(RuntimeError):
            co_core.get_charm_instance(release='icehouse_4.1')
        trilio._trilio_releases = save_releases
        co_core._get_charm_instance_function = _safe_gcif

    def test_select_trilio_release(self):
        def get_charm_class(release_pkg='trilio_pkg', package_version='4.0',
                            os_codename_exception=None,
                            version_package='trilio_pkg',
                            package_version_exception=None,
                            os_release_pkg='nova_pkg',
                            os_codename_pkg='queens',
                            trilio_source='deb https://a.io/trilio-4-2-0/ /'):

            class _TrilioCharm():

                def __init__(self):
                    self.release_pkg = release_pkg
                    self.version_package = version_package
                    self.os_release_pkg = os_release_pkg
                    self.source_config_key = 'openstack-origin'
                    self.package_codenames = {}
                    self.package_version = package_version
                    self.os_codename_exception = os_codename_exception
                    self.os_codename_pkg = os_codename_pkg
                    self.trilio_source = trilio_source

                @staticmethod
                def get_os_codename_package(pkg, code_names,
                                            apt_cache_sufficient=True):
                    if os_codename_exception:
                        raise os_codename_exception
                    else:
                        return os_codename_pkg

                @staticmethod
                def get_package_version(pkg, apt_cache_sufficient=True):
                    if package_version_exception:
                        raise package_version_exception
                    else:
                        return package_version

            return _TrilioCharm()

        _safe_rsf = co_core._release_selector_function
        co_core._release_selector_function = None
        self.patch_object(
            trilio.os_utils,
            "get_installed_semantic_versioned_packages")
        self.patch_object(trilio.os_utils, "os_release")
        self.patch_object(trilio.unitdata, "kv")
        kv_mock = mock.MagicMock()
        self.kv.return_value = kv_mock
        kv_mock.get.return_value = None
        self.patch_object(
            trilio.charms_openstack.charm.core,
            "get_charm_instance")

        trilio.make_trilio_get_charm_instance_handler()
        trilio.make_trilio_select_release_handler()
        select_trilio_release = co_core._release_selector_function
        self.get_charm_instance.return_value = get_charm_class()
        self.assertEqual(
            select_trilio_release(),
            'queens_4.0')

        # Check RuntimeError is raised if release_pkg is missing from charm
        # class
        self.get_charm_instance.return_value = get_charm_class(
            release_pkg=None)
        with self.assertRaises(RuntimeError):
            select_trilio_release()

        # Test falling back to get_installed_semantic_versioned_packages
        self.os_release.return_value = 'pike'
        self.get_installed_semantic_versioned_packages.reset_mock()
        self.get_installed_semantic_versioned_packages.return_value = ['nova']
        self.get_charm_instance.return_value = get_charm_class(
            os_codename_pkg=None)
        self.assertEqual(
            select_trilio_release(),
            'pike_4.0')

        # Check RuntimeError is raised if version_package is missing from charm
        # class
        self.get_charm_instance.return_value = get_charm_class(
            version_package=None)
        with self.assertRaises(RuntimeError):
            select_trilio_release()

        # Test falling back to get_trilio_codename_install_source
        self.get_charm_instance.return_value = get_charm_class(
            package_version_exception=ValueError)
        self.assertEqual(
            select_trilio_release(),
            'queens_4.2')
        co_core._release_selector_function = _safe_rsf


class TestTrilioVaultCharm(BaseOpenStackCharmTest):

    def setUp(self):
        super().setUp(TrilioVaultFoobar, {})
        self.patch_object(trilio.ch_core.hookenv, "log")
        self.patch_object(trilio.ch_core.hookenv, "status_set")
        self.patch_object(
            trilio.charms_openstack.charm.core,
            "get_charm_instance")
        self.patch_object(trilio, "_install_triliovault")
        self.patch_object(trilio, "_configure_triliovault_source")
        self.patch_object(trilio.fetch, "apt_update")
        self.patch_object(trilio.fetch, "apt_install")
        self.patch_object(trilio.fetch.apt_pkg, "version_compare")
        self.patch_target('config')
        self._conf = {
            'triliovault-pkg-source': 'deb https://a.io/trilio-4-2-0/ /'
        }
        self.config.get.side_effect = lambda x, b=None: self._conf.get(x, b)

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

    def test_trilio_source(self):
        self.assertEqual(
            self.target.trilio_source,
            'deb https://a.io/trilio-4-2-0/ /')

    def test_do_trilio_pkg_upgrade(self):
        self.target.do_trilio_pkg_upgrade()
        self.apt_update.assert_called_once_with()
        self.apt_install.assert_called_once_with(
            packages=['foo', 'bar'],
            options=[
                '--option', 'Dpkg::Options::=--force-confnew',
                '--option', 'Dpkg::Options::=--force-confdef'],
            fatal=True)

    def test_run_trilio_upgrade(self):
        self.patch_target('get_os_codename_package')
        self.get_os_codename_package.return_value = 'queens'
        charm_cls = mock.MagicMock()
        interface_mocks = [mock.MagicMock(), mock.MagicMock()]
        self.get_charm_instance.return_value = charm_cls
        self.target.run_trilio_upgrade(interfaces_list=interface_mocks)
        self._configure_triliovault_source.assert_called_once_with()
        charm_cls.do_trilio_pkg_upgrade.assert_called_once_with()
        charm_cls.render_with_interfaces.assert_called_once_with(
            interface_mocks)
        charm_cls.do_trilio_upgrade_db_migration.assert_called_once_with()

    def test_trilio_upgrade_available(self):
        self.patch_target('get_package_version')
        self.get_package_version.return_value = '4.1'
        self.version_compare.return_value = 1
        self.assertTrue(self.target.trilio_upgrade_available())
        self.version_compare.assert_called_once_with('4.2', '4.1')

    def test_upgrade_if_available(self):
        self.patch_target('openstack_upgrade_available')
        self.patch_target('trilio_upgrade_available')
        self.patch_target('run_upgrade')
        self.patch_target('run_trilio_upgrade')
        interface_mocks = [mock.MagicMock(), mock.MagicMock()]

        self._conf['action-managed-upgrade'] = False
        self.openstack_upgrade_available.return_value = True
        self.trilio_upgrade_available.return_value = True
        self.target.upgrade_if_available(interface_mocks)
        self.run_upgrade.assert_called_once_with(
            interfaces_list=interface_mocks)
        self.run_trilio_upgrade.assert_called_once_with(
            interfaces_list=interface_mocks)

        self.run_upgrade.reset_mock()
        self.run_trilio_upgrade.reset_mock()
        self._conf['action-managed-upgrade'] = True
        self.openstack_upgrade_available.return_value = True
        self.trilio_upgrade_available.return_value = True
        self.target.upgrade_if_available(interface_mocks)
        self.assertFalse(self.run_upgrade.called)
        self.assertFalse(self.run_trilio_upgrade.called)


class TestTrilioVaultSubordinateCharm(BaseOpenStackCharmTest):

    def setUp(self):
        super().setUp(TrilioVaultFoobarSubordinate, {})
        self.patch_object(trilio, "_install_triliovault")
        self.patch_object(trilio, "_configure_triliovault_source")
        self.patch_object(trilio.fetch, "apt_update")

    def test_configure_source(self):
        self.patch_object(trilio.charms_openstack.charm.OpenStackCharm,
                          'configure_source')
        self.target.configure_source()
        self._configure_triliovault_source.assert_called_once_with()
        self.configure_source.assert_not_called()
        self.apt_update.assert_called_once_with(fatal=True)


class TestBaseTrilioCharmMeta(BaseTestCase):

    def setUp(self):
        self.save_releases = trilio._trilio_releases
        super().setUp()
        self.patch_object(trilio.fetch.apt_pkg, 'version_compare')

        def _version_compare(ver1, ver2):
            if float(ver1) > float(ver2):
                return 1
            elif float(ver1) < float(ver2):
                return -1
            else:
                return 0
        self.version_compare.side_effect = _version_compare

    def tearDown(self):
        super().tearDown()
        trilio._trilio_releases = self.save_releases

    def register_classes(self):

        class TrilioQueens40(metaclass=trilio.BaseTrilioCharmMeta):

            release = 'queens'
            trilio_release = '4.0'

        class TrilioQueens41(metaclass=trilio.BaseTrilioCharmMeta):

            release = 'queens'
            trilio_release = '4.1'

        class TrilioRocky40(metaclass=trilio.BaseTrilioCharmMeta):

            release = 'rocky'
            trilio_release = '4.0'

        return {
            'queens_4.0': TrilioQueens40,
            'queens_4.1': TrilioQueens41,
            'rocky_4.0': TrilioRocky40}

    def register_classes_missing_key(self):

        class TrilioQueens40(metaclass=trilio.BaseTrilioCharmMeta):

            release = 'queens'

    def register_classes_wrong_pkg_type(self):

        class TrilioQueens40(metaclass=trilio.BaseTrilioCharmMeta):

            release = 'queens'
            trilio_release = '4.1'
            package_type = 'up2date'

    def register_classes_duplicate(self):

        class TrilioQueens40A(metaclass=trilio.BaseTrilioCharmMeta):

            release = 'queens'
            trilio_release = '4.0'

        class TrilioQueens40B(metaclass=trilio.BaseTrilioCharmMeta):

            release = 'queens'
            trilio_release = '4.0'

    def test_class_register(self):
        charm_classes = self.register_classes()
        self.maxDiff = None
        self.assertEqual(
            trilio._trilio_releases,
            {
                'queens': {
                    trilio.AptPkgVersion('4.0'): {
                        'deb': charm_classes['queens_4.0']},
                    trilio.AptPkgVersion('4.1'): {
                        'deb': charm_classes['queens_4.1']}},
                'rocky': {
                    trilio.AptPkgVersion('4.0'): {
                        'deb': charm_classes['rocky_4.0']}}})

    def test_class_register_missing_key(self):
        with self.assertRaises(RuntimeError):
            self.register_classes_missing_key()

    def test_class_register_wrong_pkg_type(self):
        with self.assertRaises(RuntimeError):
            self.register_classes_wrong_pkg_type()

    def test_class_register_duplicate(self):
        with self.assertRaises(RuntimeError):
            self.register_classes_duplicate()
