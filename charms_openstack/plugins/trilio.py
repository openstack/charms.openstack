# Copyright 2019 Canonical Ltd
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

import base64
import os

import re
from urllib.parse import urlparse

import charms_openstack.adapters
import charms_openstack.charm

import charmhelpers.core as ch_core
import charmhelpers.fetch as fetch
import charmhelpers.core.unitdata as unitdata
import charmhelpers.contrib.openstack.utils as os_utils

import charms.reactive as reactive


TV_MOUNTS = "/var/triliovault-mounts"

# Location of the certificate file to use when talking to S3 endpoint.
S3_SSL_CERT_FILE = '/usr/share/ca-certificates/charm-s3.cert'

# Used to store the discovered release version for caching between invocations
TRILIO_RELEASE_KEY = 'charmers.trilio-release-version'

# _trilio_releases{} is a dictionary of release -> class that is instantiated
# according to the release that is being requested.  i.e. a charm can
# handle more than one release. The BaseOpenStackCharm() derived class sets the
# `release` variable to indicate which OpenStack release that the charm
# supports # and `trilio_release` to indicate which Trilio release the charm
# supports.  # Any subsequent releases that need a different/specialised charm
# uses the # `release` and `trilio_release` class properties to indicate that
# it handles those releases onwards.
_trilio_releases = {}


@charms_openstack.adapters.config_property
def trilio_properties(cls):
    """Trilio properties additions for config adapter.

    :param cls: Configuration Adapter class
    :type cls: charms_openstack.adapters.DefaultConfigurationAdapter
    """
    cur_ver = cls.charm_instance.release_pkg_version()
    comp = fetch.apt_pkg.version_compare(cur_ver, '4.1')
    if comp >= 0:
        return {
            'db_type': 'dedicated',
            'transport_type': 'dmapi'}
    else:
        return {
            'db_type': 'legacy',
            'transport_type': 'legacy'}


@charms_openstack.adapters.config_property
def trilio_s3_cert_config(cls):
    """Trilio S3 certificate config

    :param cls: Configuration Adapter class
    :type cls: charms_openstack.adapters.DefaultConfigurationAdapter
    """
    s3_cert_config = {}
    config = ch_core.hookenv.config('tv-s3-ssl-cert')
    if config:
        s3_cert_config = {
            'cert_file': S3_SSL_CERT_FILE,
            'cert_data': base64.b64decode(config).decode('utf-8')}
    return s3_cert_config


class AptPkgVersion():
    """Allow package version to be compared."""

    def __init__(self, version):
        self.version = version

    def __lt__(self, other):
        return fetch.apt_pkg.version_compare(self.version, other.version) == -1

    def __le__(self, other):
        return self.__lt__(other) or self.__eq__(other)

    def __gt__(self, other):
        return fetch.apt_pkg.version_compare(self.version, other.version) == 1

    def __ge__(self, other):
        return self.__gt__(other) or self.__eq__(other)

    def __eq__(self, other):
        return fetch.apt_pkg.version_compare(self.version, other.version) == 0

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return self.version

    def __hash__(self):
        return hash(repr(self))


class NFSShareNotMountedException(Exception):
    """Signal that the trilio nfs share is not mount"""

    pass


class UnitNotLeaderException(Exception):
    """Signal that the unit is not the application leader"""

    pass


class GhostShareAlreadyMountedException(Exception):
    """Signal that a ghost share is already mounted"""

    pass


class MismatchedConfigurationException(Exception):
    """Signal that nfs-shares and ghost-shares are mismatched"""

    pass


def _configure_triliovault_source():
    """Configure triliovault specific package sources in addition to
    any general openstack package sources (via openstack-origin)
    """
    with open(
        "/etc/apt/sources.list.d/trilio-gemfury-sources.list", "w"
    ) as tsources:
        tsources.write(ch_core.hookenv.config("triliovault-pkg-source"))


def _install_triliovault(charm):
    """Install packages dealing with Trilio nuances for upgrades as well

    Set the 'upgrade.triliovault' flag to ensure that any triliovault
    packages are upgraded.
    """
    packages = charm.all_packages
    if not reactive.is_flag_set("upgrade.triliovault"):
        packages = fetch.filter_installed_packages(
            charm.all_packages)

    if packages:
        ch_core.hookenv.status_set('maintenance',
                                   'Installing/upgrading packages')
        fetch.apt_install(packages, fatal=True)

    # AJK: we set this as charms can use it to detect installed state
    charm.set_state('{}-installed'.format(charm.name))
    charm.update_api_ports()

    # NOTE(jamespage): clear upgrade flag if set
    if reactive.is_flag_set("upgrade.triliovault"):
        reactive.clear_flag('upgrade.triliovault')


def get_trilio_codename_install_source(trilio_source):
    """Derive codename from trilio source string.

    Try and derive a trilio version from a deb string like:
    'deb [trusted=yes] https://apt.fury.io/triliodata-4-0/ /'

    :param trilio_source: Trilio source
    :type trilio_source: str
    :returns: Trilio version
    :rtype: str
    :raises: AssertionError
    """
    deb_url = trilio_source.split()[-2]
    code = re.findall(r'-(\d*-\d*)', urlparse(deb_url).path)
    assert len(code) == 1, "Cannot derive release from {}".format(deb_url)
    new_os_rel = code[0].replace('-', '.')
    return new_os_rel


def make_trilio_get_charm_instance_handler():
    """This handler sets the get_charm_instance function.
    """

    @charms_openstack.charm.core.register_get_charm_instance
    def get_trilio_charm_instance(release=None, package_type='deb', *args,
                                  **kwargs):
        """Get an instance of the charm based on the release (or use the
        default if release is None).

        Note that it passes args and kwargs to the class __init__() method.

        :param release: String representing release wanted. Should be of the
                        form '<openstack_release>_<trilio_release>'
                        eg 'queens_4.0'
        :type release: str
        :param package_type: The package type required
        :type package_type: str
        :returns: Charm class
        :rtype: BaseOpenStackCharm() derived class according to cls.releases
        """
        cls = None
        known_os_releases = sorted(_trilio_releases.keys())
        if release is None:
            # If release is None then select the class(es) which supports the
            # most recent OpenStack release, from within this set select the
            # class that supports the most recent Trilio release.
            os_release = known_os_releases[-1]
            known_trilio_releases = sorted(_trilio_releases[os_release].keys())
            trilio_release = known_trilio_releases[-1]
            cls = _trilio_releases[os_release][trilio_release][package_type]
        else:
            os_release, trilio_release = release.split('_')
            trilio_release = AptPkgVersion(trilio_release)
            if os_release not in os_utils.OPENSTACK_RELEASES:
                raise RuntimeError(
                    "Release {} is not a known OpenStack release?".format(
                        os_release))
            os_release_index = os_utils.OPENSTACK_RELEASES.index(os_release)
            if (os_release_index <
                    os_utils.OPENSTACK_RELEASES.index(known_os_releases[0])):
                raise RuntimeError(
                    "Release {} is not supported by this charm. Earliest "
                    "support is {} release".format(
                        os_release,
                        known_os_releases[0]))
            else:
                known_trilio_releases = []
                # Search through the dictionary of registered charm classes
                # looking for the most recent group which can support
                # `os_release`
                for known_os_release in reversed(known_os_releases):
                    _idx = os_utils.OPENSTACK_RELEASES.index(known_os_release)
                    if os_release_index >= _idx:
                        trilio_classes = _trilio_releases[known_os_release]
                        known_trilio_releases = sorted(trilio_classes.keys())
                        break
                # Search through the dictionary of registered charm classes
                # that support `known_os_release` onwards and look for the
                # class # which supports the most recent trilio release which
                # is <= `trilio_release`
                for known_trilio_release in reversed(known_trilio_releases):
                    if known_trilio_release <= trilio_release:
                        cls = trilio_classes[known_trilio_release][
                            package_type]
                        # Found a class so exit loop
                        break
        if cls is None:
            raise RuntimeError("Release {} is not supported".format(release))
        return cls(release=os_release, *args, **kwargs)


def make_trilio_handlers():
    """This handler sets the trilio release selector get_charm_instance funcs.
    """
    make_trilio_get_charm_instance_handler()
    make_trilio_select_release_handler()


def make_trilio_select_release_handler():
    """This handler sets the release selector function.
    """

    @charms_openstack.charm.core.register_os_release_selector
    def select_trilio_release():
        """Determine the OpenStack and Trilio release

        Determine the OpenStack release based on the `singleton.os_release_pkg`
        that is installed. If it is not installed look for and exanine other
        semantic versioned packages. If both those tactics fail fall back to
        checking the charm `openstack-origin` option.

        Determine the Trilio release based on the `singleton.version_package`
        that is installed. If it is not installed fall back to checking the
        charm `triliovault-pkg-source` option.

        Note that this function caches the release after the first install so
        that it doesn't need to keep going and getting it from the package
        information.
        """

        singleton = None
        # Search for target OpenStack Release
        os_release_version = unitdata.kv().get(
            charms_openstack.charm.core.OPENSTACK_RELEASE_KEY,
            None)
        if os_release_version is None:
            try:
                # First make an attempt of determining release from a charm
                # instance defined package codename dictionary.
                singleton = charms_openstack.charm.core.get_charm_instance()
                if singleton.release_pkg is None:
                    raise RuntimeError("release_pkg is not set")
                os_release_version = singleton.get_os_codename_package(
                    singleton.os_release_pkg, singleton.package_codenames,
                    apt_cache_sufficient=(not singleton.source_config_key))
                if os_release_version is None:
                    # Surprisingly get_os_codename_package called with
                    # ``Fatal=True`` does not raise an error when the charm
                    # class ``package_codenames`` map does not contain package
                    # or major version.  We'll handle it here instead of
                    # changing the API of the method.
                    raise ValueError
            except (AttributeError, ValueError):
                try:
                    pkgs = os_utils.get_installed_semantic_versioned_packages()
                    pkg = pkgs[0]
                except IndexError:
                    # A non-existent package will cause os_release to try other
                    # tactics for deriving the release.
                    pkg = 'dummy-package'
                os_release_version = os_utils.os_release(
                    pkg, source_key=singleton.source_config_key)
            unitdata.kv().set(
                charms_openstack.charm.core.OPENSTACK_RELEASE_KEY,
                os_release_version)
            unitdata.kv().flush()

        # Search for target Trilio Release
        trilio_release_version = unitdata.kv().get(TRILIO_RELEASE_KEY, None)
        if trilio_release_version is None:
            if not singleton:
                singleton = charms_openstack.charm.core.get_charm_instance()
            if singleton.version_package is None:
                raise RuntimeError("version_package is not set")
            try:
                trilio_release_version = singleton.get_package_version(
                    singleton.version_package)
            except (AttributeError, ValueError):
                trilio_release_version = get_trilio_codename_install_source(
                    singleton.trilio_source)
            unitdata.kv().set(TRILIO_RELEASE_KEY, trilio_release_version)
            unitdata.kv().flush()

        return '{}_{}'.format(os_release_version, trilio_release_version)


class BaseTrilioCharmMeta(charms_openstack.charm.core.BaseOpenStackCharmMeta):
    """Metaclass to handle registering charm classes by their supported
       OpenStack release, Trilio release and package typea

       _trilio_releases has the form::

           {
               'Openstack Code Name': {
                   'Trilio Package Veersion': {
                       'Package Type': <charm class>}},
    """

    def __init__(cls, name, mro, members):
        """Receive the BaseOpenStackCharm() (derived) class and store the
        release that it works against.  Each class defines a 'release' which
        corresponds to the Openstack release that it handles. The class should
        also specify 'trilio_release' which defines the Trilio releases it can
        handle.

        :param name: string for class name.
        :param mro: tuple of base classes.
        :param members: dictionary of name to class attribute (f, p, a, etc.)
        """
        # Do not attempt to calculate the release for an abstract class
        if members.get('abstract_class', False):
            return
        if all(key in members.keys() for key in ['release', 'trilio_release']):
            package_type = members.get('package_type', 'deb')
            if package_type not in ('deb', 'snap'):
                raise RuntimeError(
                    "Package type {} is not a known type"
                    .format(package_type))
            release = members['release']
            trilio_release = AptPkgVersion(members['trilio_release'])
            if release not in os_utils.OPENSTACK_RELEASES:
                raise RuntimeError(
                    "Release {} is not a known OpenStack release"
                    .format(release))
            try:
                _pre = _trilio_releases[release][trilio_release][package_type]
            except KeyError:
                # All good this comination has not been registered yet.
                pass
            else:
                raise RuntimeError(
                    "Release {} + {} defined more than once in classes {} and "
                    "{} (at least)"
                    .format(release,
                            trilio_release,
                            _pre.__name__,
                            name))
            # store the class against the release.
            if release not in _trilio_releases:
                _trilio_releases[release] = {}
            if trilio_release not in _trilio_releases[release]:
                _trilio_releases[release][trilio_release] = {}
            _trilio_releases[release][trilio_release][package_type] = cls
        else:
            raise RuntimeError(
                "class '{}' must define both the release it supports using "
                "the 'release' class property and the trilio release it "
                "supports using the 'trilio_release' class property.".format(
                    name))


class TrilioVaultCharmMixin():
    """The TrilioVaultCharm class provides common specialisation of certain
    functions for the Trilio charm set and is designed for use alongside
    other base charms.openstack classes
    """

    abstract_class = True

    def __init__(self, **kwargs):
        try:
            del kwargs['trilio_release']
        except KeyError:
            pass
        super().__init__(**kwargs)

    def configure_source(self):
        """Configure triliovault specific package sources in addition to
        any general openstack package sources (via openstack-origin)
        """
        _configure_triliovault_source()
        super().configure_source()

    def install(self):
        """Install packages dealing with Trilio nuances for upgrades as well
        """
        self.configure_source()
        _install_triliovault(self)

    def series_upgrade_complete(self):
        """Re-configure sources post series upgrade"""
        super().series_upgrade_complete()
        self.configure_source()

    @property
    def trilio_source(self):
        """Trilio source config option"""
        return self.config.get("triliovault-pkg-source")

    def do_trilio_pkg_upgrade(self):
        """Upgrade Trilio packages
        """
        new_os_rel = get_trilio_codename_install_source(
            self.trilio_source)
        ch_core.hookenv.log('Performing Trilio upgrade to %s.' % (new_os_rel))

        dpkg_opts = [
            '--option', 'Dpkg::Options::=--force-confnew',
            '--option', 'Dpkg::Options::=--force-confdef',
        ]
        fetch.apt_update()
        fetch.apt_install(
            packages=self.all_packages,
            options=dpkg_opts,
            fatal=True)
        self.remove_obsolete_packages()

    def do_trilio_upgrade_db_migration(self):
        """Run Trilio DB sync

        Trilio charms sync_cmd refers to a trilio db sync.

        """
        super().do_openstack_upgrade_db_migration()

    def run_trilio_upgrade(self, interfaces_list=None):
        """
        :param interfaces_list: List of instances of interface classes
        :returns: None
        """
        ch_core.hookenv.status_set('maintenance', 'Running openstack upgrade')
        cur_os_release = self.get_os_codename_package(
            self.os_release_pkg,
            self.package_codenames)
        new_trilio_release = get_trilio_codename_install_source(
            self.trilio_source)
        new_release = '{}_{}'.format(cur_os_release, new_trilio_release)
        unitdata.kv().set(TRILIO_RELEASE_KEY, new_trilio_release)
        _configure_triliovault_source()
        target_charm = charms_openstack.charm.core.get_charm_instance(
            new_release)
        target_charm.do_trilio_pkg_upgrade()
        target_charm.render_with_interfaces(interfaces_list)
        target_charm.do_trilio_upgrade_db_migration()

    def trilio_upgrade_available(self, package=None):
        """Check if an OpenStack upgrade is available

        :param package: str Package name to use to check upgrade availability
        :returns: bool
        """
        cur_vers = self.get_package_version(package)
        avail_vers = get_trilio_codename_install_source(
            self.trilio_source)
        return fetch.apt_pkg.version_compare(avail_vers, cur_vers) == 1

    def upgrade_if_available(self, interfaces_list):
        if self.openstack_upgrade_available(self.os_release_pkg):
            if self.config.get('action-managed-upgrade', False):
                ch_core.hookenv.log('Not performing OpenStack upgrade as '
                                    'action-managed-upgrade is enabled')
            else:
                self.run_upgrade(interfaces_list=interfaces_list)
        if self.trilio_upgrade_available(
                package=self.trilio_version_package()):
            if self.config.get('action-managed-upgrade', False):
                ch_core.hookenv.log('Not performing Trilio upgrade as '
                                    'action-managed-upgrade is enabled')
            else:
                self.run_trilio_upgrade(interfaces_list=interfaces_list)

    @classmethod
    def trilio_version_package(cls):
        raise NotImplementedError

    @property
    def version_package(self):
        return self.trilio_version_package()

    @property
    def release_pkg(self):
        return self.trilio_version_package()

    @classmethod
    def release_pkg_version(cls):
        return cls.get_package_version(cls.trilio_version_package())


class TrilioVaultCharm(TrilioVaultCharmMixin,
                       charms_openstack.charm.HAOpenStackCharm,
                       metaclass=BaseTrilioCharmMeta):

    abstract_class = True


class TrilioVaultSubordinateCharm(TrilioVaultCharmMixin,
                                  charms_openstack.charm.OpenStackCharm,
                                  metaclass=BaseTrilioCharmMeta):

    abstract_class = True

    def configure_source(self):
        """Configure TrilioVault specific package sources
        """
        _configure_triliovault_source()
        fetch.apt_update(fatal=True)


class TrilioVaultCharmGhostAction(object):
    """Shared 'ghost share' action for TrilioVault charms

    It is designed as a mixin, and is separated out so that it is easier to
    maintain.

    i.e.

    class TrilioWLMCharm(TrilioVaultCharm,
                         TrilioVaultCharmGhostAction):
        ... stuff ...
    """

    def _encode_endpoint(self, backup_endpoint):
        """base64 encode an backup endpoint for cross mounting support"""
        return base64.b64encode(backup_endpoint.encode()).decode()

    def ghost_nfs_share(self, ghost_shares):
        """Bind mount local NFS shares to remote NFS paths

        :param ghost_shares: Comma separated NFS shares URL to ghost
        :type ghost_shares: str
        """
        ghost_shares = ghost_shares.split(',')
        nfs_shares = ch_core.hookenv.config("nfs-shares").split(',')
        try:
            share_mappings = [
                (nfs_shares[i], ghost_shares[i])
                for i in range(0, len(nfs_shares))
            ]
        except IndexError:
            raise MismatchedConfigurationException(
                "ghost-shares and nfs-shares are different lengths"
            )
        for local_share, ghost_share in share_mappings:
            self._ghost_nfs_share(local_share, ghost_share)

    def trilio_share_mounted(self, share_path):
        """Check if share_path is mounted

        :param local_share: Local NFS share URL
        :type local_share: str
        :returns: Whether share is mounted
        :rtype: bool
        """
        _share_path = os.path.join(
            TV_MOUNTS,
            self._encode_endpoint(share_path))
        current_mounts = [mount[0] for mount in ch_core.host.mounts()]
        return _share_path in current_mounts

    def _ghost_nfs_share(self, local_share, ghost_share):
        """Bind mount a local unit NFS share to another sites location

        :param local_share: Local NFS share URL
        :type local_share: str
        :param ghost_share: NFS share URL to ghost
        :type ghost_share: str
        """
        nfs_share_path = os.path.join(
            TV_MOUNTS,
            self._encode_endpoint(local_share)
        )
        ghost_share_path = os.path.join(
            TV_MOUNTS, self._encode_endpoint(ghost_share)
        )

        if not self.trilio_share_mounted(local_share):
            # Trilio has not mounted the NFS share so return
            raise NFSShareNotMountedException(
                "nfs-share ({}) not mounted".format(
                    local_share
                )
            )

        if self.trilio_share_mounted(ghost_share):
            # bind mount already setup so return
            raise GhostShareAlreadyMountedException(
                "ghost mountpoint ({}) already bound".format(ghost_share_path)
            )

        if not os.path.exists(ghost_share_path):
            os.mkdir(ghost_share_path)

        ch_core.host.mount(nfs_share_path, ghost_share_path, options="bind")


class TrilioVault42CharmGhostAction(TrilioVaultCharmGhostAction):

    def _encode_endpoint_uri(self, backup_endpoint):
        """base64 encode a backup uri for cross mounting support"""
        return base64.b64encode(backup_endpoint.encode()).decode()

    def _encode_endpoint_path(self, backup_endpoint):
        """base64 encode an backup path for cross mounting support"""
        return base64.b64encode(
            str.encode(urlparse(backup_endpoint).path)).decode()

    def _encode_endpoint(self, backup_endpoint):
        """base64 encode an backup endpoint for cross mounting support"""
        return self._encode_endpoint_path(backup_endpoint)

    def trilio_share_mounted(self, share_path):
        """Check if share_path is mounted

        :param local_share: Local NFS share URL
        :type local_share: str
        :returns: Whether share is mounted
        :rtype: bool
        """
        mount_paths = [
            os.path.join(
                TV_MOUNTS,
                self._encode_endpoint_path(share_path)
            ),
            os.path.join(
                TV_MOUNTS,
                self._encode_endpoint_uri(share_path)
            )]
        current_mounts = [mount[0] for mount in ch_core.host.mounts()]
        return any(m in current_mounts for m in mount_paths)
