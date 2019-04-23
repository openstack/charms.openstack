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

import collections
import os
import shutil
import socket
import subprocess

import charms_openstack.charm
from charms_openstack.charm.classes import SNAP_PATH_PREFIX_FORMAT

import charmhelpers.core as ch_core


class BaseOpenStackCephCharm(object):
    """Base class for Ceph classes.

    Provided as a mixin so charm authors can compose the charm class
    appropriate for their use case.
    """
    # Ceph cluster name is used for naming of various configuration files and
    # directories.  It is also used by Ceph command line tools to interface
    # with multiple distinct Ceph clusters from one place.
    ceph_cluster_name = 'ceph'

    # Both consumers and providers of Ceph services share a pattern of the
    # need for a key and a keyring file on disk, they also share naming
    # conventions.
    # The most used key naming convention is for all instances of a service
    # to share a key named after the service.
    # Some services follow a different pattern with unique key names for each
    # instance of a service.  (e.g. RadosGW Multi-Site, RBD Mirroring)
    ceph_key_per_unit_name = False

    # Ceph service name and service type is used for sectioning of
    # ``ceph.conf`, appropriate naming of keys and keyring files.  By default
    # ceph service name is determined from `application_name` property.
    # If this does not fit your use case you can override.
    ceph_service_name_override = ''
    # Unless you are writing a charm providing Ceph mon|osd|mgr|mds services
    # this should probably be left as-is.
    ceph_service_type = 'client'

    # Path prefix to where the Ceph keyring should be stored.
    ceph_keyring_path_prefix = '/etc/ceph'

    @property
    @ch_core.hookenv.cached
    def application_name(self):
        """Provide the name this instance of the charm has in the Juju model.

        :returns: Application name
        :rtype: str
        """
        return ch_core.hookenv.application_name()

    @property
    def snap_path_prefix(self, snap=None):
        """Provide the path prefix for a snap.

        :param snap: (Optional) The snap you want to build a path prefix for
                     If not provided will attempt to build for the first snap
                     listed in self.snaps.
        :type snap: str
        :returns: Path prefix for snap or the empty string ('')
        :rtype: str
        """
        if snap:
            return SNAP_PATH_PREFIX_FORMAT.format(snap)
        elif self.snaps:
            return SNAP_PATH_PREFIX_FORMAT.format(self.snaps[0])
        else:
            return ''

    @property
    def ceph_service_name(self):
        """Provide Ceph service name for use in config, key and keyrings.

        :returns: Ceph service name
        :rtype: str
        """
        return (self.ceph_service_name_override or
                self.application_name)

    @property
    def ceph_key_name(self):
        """Provide Ceph key name for the charm managed service.

        :returns: Ceph key name
        :rtype: str
        """
        base_key_name = '{}.{}'.format(
            self.ceph_service_type,
            self.ceph_service_name)
        if self.ceph_key_per_unit_name:
            return '{}.{}'.format(
                base_key_name,
                socket.gethostname())
        else:
            return base_key_name

    @property
    def ceph_keyring_path(self):
        """Provide a path to where the Ceph keyring should be stored.

        :returns: Path to directory
        :rtype: str
        """
        return os.path.join(self.snap_path_prefix,
                            self.ceph_keyring_path_prefix)

    def ceph_keyring_absolute_path(self, cluster_name=None):
        """Provide absolute path to keyring file.

        :param cluster_name: (Optional) Name of Ceph cluster to operate on.
                             Defaults to value of ``self.ceph_cluster_name``.
        :type cluster_name: str
        :returns: Absolute path to keyring file
        :rtype: str
        """
        keyring_name = ('{}.{}.keyring'
                        .format(cluster_name or self.ceph_cluster_name,
                                self.ceph_key_name))
        keyring_absolute_path = os.path.join(self.ceph_keyring_path,
                                             keyring_name)
        return keyring_absolute_path

    def configure_ceph_keyring(self, key, cluster_name=None):
        """Creates or updates a Ceph keyring file.

        :param key: Key data
        :type key: str
        :param cluster_name: (Optional) Name of Ceph cluster to operate on.
                             Defaults to value of ``self.ceph_cluster_name``.
        :type cluster_name: str
        :returns: Absolute path to keyring file
        :rtype: str
        :raises: subprocess.CalledProcessError, OSError
        """
        if not os.path.isdir(self.ceph_keyring_path):
            ch_core.host.mkdir(self.ceph_keyring_path,
                               owner=self.user, group=self.group, perms=0o750)
        keyring_absolute_path = self.ceph_keyring_absolute_path(
            cluster_name=cluster_name)
        cmd = [
            'ceph-authtool', keyring_absolute_path,
            '--create-keyring', '--name={}'.format(self.ceph_key_name),
            '--add-key', key, '--mode', '0600',
        ]
        try:
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError as cp:
            if not cp.returncode == 1:
                raise
            # the version of ceph-authtool on the system does not have
            # --mode command line argument
            subprocess.check_call(cmd[:-2])
            os.chmod(keyring_absolute_path, 0o600)
        shutil.chown(keyring_absolute_path, user=self.user, group=self.group)
        return keyring_absolute_path

    def delete_ceph_keyring(self, cluster_name=None):
        """Deletes an existing Ceph keyring file.

        :param cluster_name: (Optional) Name of Ceph cluster to operate on.
                             Defaults to value of ``self.ceph_cluster_name``.
        :type cluster_name: str
        :returns: Absolute path to the now removed keyring file or empty string
        :rtype: str
        """
        keyring_absolute_path = self.ceph_keyring_absolute_path(
            cluster_name=cluster_name)
        try:
            os.remove(keyring_absolute_path)
            return keyring_absolute_path
        except OSError:
            return ''


class CephCharm(charms_openstack.charm.OpenStackCharm,
                BaseOpenStackCephCharm):
    """Class for charms deploying Ceph services.

    It provides useful defaults to make release detection work when no
    OpenStack packages are installed.

    Ceph services also have different preferences for placement of keyring
    files.

    Code useful for and shared among charms deploying software that want to
    consume Ceph services should be added to the BaseOpenStackCephCharm base
    class.
    """

    abstract_class = True

    # Ubuntu Ceph packages are distributed along with the Ubuntu OpenStack
    # packages, both for distro and UCA.
    # Map OpenStack release to the Ceph release distributed with it.
    package_codenames = {
        'ceph-common': collections.OrderedDict([
            ('0', 'icehouse'),  # 0.80   Firefly
            ('10', 'mitaka'),   # 10.2.x Jewel
            ('12', 'pike'),     # 12.2.x Luminous
            ('13', 'rocky'),    # 13.2.x Mimic
        ]),
    }

    # Package to determine application version from
    version_package = release_pkg = 'ceph-common'

    # release = the first release in which this charm works.  Refer to
    # package_codenames variable above for table of OpenStack to Ceph releases.
    release = 'icehouse'

    # Python version used to execute installed workload
    python_version = 3

    # The name of the repository source configuration option.
    # The ``ceph`` layer provides the ``config.yaml`` counterpart.
    source_config_key = 'source'

    # To make use of the CephRelationAdapter the derived charm class should
    # define its own RelationAdapters class that inherits from
    # ``adapters.OpenStackRelationAdapters`` or
    # ``adapters.OpenStackAPIRelationAdapters``, whichever is most relevant.
    #
    # The custom RelationAdapters class should map the relation that provides
    # the interface with a``mon_hosts`` property or function to the
    # CephRelationAdapter by extending the ``relation_adapters`` dict.
    #
    # There is currently no standardization of relevant relation names among
    # the Ceph providing or consuming charms, so it does currently not make
    # sense to add this to the default relation adapters.
    # adapters_class = MyCephCharmRelationAdapters

    # Path prefix to where the Ceph keyring should be stored.
    ceph_keyring_path_prefix = '/var/lib/ceph'

    @property
    def ceph_keyring_path(self):
        """Provide a path to where the Ceph keyring should be stored.

        :returns: Path to directory
        :rtype: str
        """
        return os.path.join(self.snap_path_prefix,
                            self.ceph_keyring_path_prefix,
                            self.ceph_service_name)

    def configure_ceph_keyring(self, key, cluster_name=None):
        """Override parent function to add symlink in ``/etc/ceph``."""
        keyring_absolute_path = super().configure_ceph_keyring(
            key, cluster_name=cluster_name)
        symlink_absolute_path = os.path.join(
            '/etc/ceph',
            os.path.basename(keyring_absolute_path))
        if os.path.exists(symlink_absolute_path):
            try:
                if (os.readlink(symlink_absolute_path) !=
                        keyring_absolute_path):
                    os.remove(symlink_absolute_path)
                else:
                    # Symlink exists and points to expected location
                    return
            except OSError:
                # We expected a symlink.
                # Fall through and let os.symlink raise error.
                pass
        os.symlink(keyring_absolute_path, symlink_absolute_path)

    def install(self):
        """Install packages related to this charm based on
        contents of self.packages attribute, after first
        configuring the installation source.
        """
        self.configure_source()
        super().install()
