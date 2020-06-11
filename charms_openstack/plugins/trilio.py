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

import charms_openstack.charm

import charmhelpers.core as ch_core
import charmhelpers.fetch as fetch

import charms.reactive as reactive


TV_MOUNTS = "/var/triliovault-mounts"


class NFSShareNotMountedException(Exception):
    """Signal that the trilio nfs share is not mount"""

    pass


class UnitNotLeaderException(Exception):
    """Signal that the unit is not the application leader"""

    pass


class GhostShareAlreadyMountedException(Exception):
    """Signal that a ghost share is already mounted"""

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


class TrilioVaultCharm(charms_openstack.charm.HAOpenStackCharm):
    """The TrilioVaultCharm class provides common specialisation of certain
    functions for the Trilio charm set and is designed for use alongside
    other base charms.openstack classes
    """

    abstract_class = True

    def __init__(self, **kwargs):
        super(TrilioVaultCharm, self).__init__(**kwargs)

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


class TrilioVaultSubordinateCharm(charms_openstack.charm.OpenStackCharm):
    """The TrilioVaultSubordinateCharm class provides common specialisation
    of certain functions for the Trilio charm set and is designed for use
    alongside other base charms.openstack classes for subordinate charms
    """

    abstract_class = True

    def __init__(self, **kwargs):
        super(TrilioVaultSubordinateCharm, self).__init__(**kwargs)

    def configure_source(self):
        """Configure TrilioVault specific package sources
        """
        _configure_triliovault_source()
        fetch.apt_update(fatal=True)

    def install(self):
        """Install packages dealing with Trilio nuances for upgrades as well
        """
        self.configure_source()
        _install_triliovault(self)

    def series_upgrade_complete(self):
        """Re-configure sources post series upgrade"""
        super().series_upgrade_complete()
        self.configure_source()


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

    def ghost_nfs_share(self, ghost_share):
        """Bind mount the local units nfs share to another sites location

        :param ghost_share: NFS share URL to ghost
        :type ghost_share: str
        """
        nfs_share_path = os.path.join(
            TV_MOUNTS,
            self._encode_endpoint(ch_core.hookenv.config("nfs-shares"))
        )
        ghost_share_path = os.path.join(
            TV_MOUNTS, self._encode_endpoint(ghost_share)
        )

        current_mounts = [mount[0] for mount in ch_core.host.mounts()]

        if nfs_share_path not in current_mounts:
            # Trilio has not mounted the NFS share so return
            raise NFSShareNotMountedException(
                "nfs-shares ({}) not mounted".format(
                    ch_core.hookenv.config("nfs-shares")
                )
            )

        if ghost_share_path in current_mounts:
            # bind mount already setup so return
            raise GhostShareAlreadyMountedException(
                "ghost mountpoint ({}) already bound".format(ghost_share_path)
            )

        if not os.path.exists(ghost_share_path):
            os.mkdir(ghost_share_path)

        ch_core.host.mount(nfs_share_path, ghost_share_path, options="bind")
