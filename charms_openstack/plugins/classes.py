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
import enum
import os
import shutil
import socket
import subprocess

import charms_openstack.charm
from charms_openstack.charm.classes import SNAP_PATH_PREFIX_FORMAT

import charmhelpers.core as ch_core
import charmhelpers.contrib.openstack.policyd as ch_policyd


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

    class CephServiceType(enum.Enum):
        """Ceph service type."""
        client = 'client'
        mds = 'mds'
        mgr = 'mgr'
        mon = 'mon'
        osd = 'osd'

        def __str__(self):
            """Return string representation of value.

            :returns: string representation of value.
            :rtype: str
            """
            return self.value

    ceph_service_type = CephServiceType.client

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
        if self.ceph_service_type == self.CephServiceType.client:
            base_key_name = '{}.{}'.format(
                self.ceph_service_type,
                self.ceph_service_name)
        else:
            base_key_name = self.ceph_service_name

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
        if self.ceph_service_type == self.CephServiceType.client:
            keyring_name = ('{}.{}.keyring'
                            .format(cluster_name or self.ceph_cluster_name,
                                    self.ceph_key_name))
        else:
            keyring_name = 'keyring'

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
            ('14', 'train'),    # 14.2.x Nautilus
            ('15', 'ussuri'),   # 15.2.x Octopus
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

    def __init__(self, **kwargs):
        """Initialize class."""
        super().__init__(**kwargs)
        self.hostname = socket.gethostname()

    @property
    def ceph_keyring_path(self):
        """Provide a path to where the Ceph keyring should be stored.

        :returns: Path to directory
        :rtype: str
        """
        keyring_path_components = [
            self.snap_path_prefix,
            self.ceph_keyring_path_prefix,
            self.ceph_service_name]

        if self.ceph_service_type != self.CephServiceType.client:
            keyring_path_components.append(
                '{}-{}'.format(self.ceph_cluster_name,
                               self.hostname))

        return os.path.join(*keyring_path_components)

    def configure_ceph_keyring(self, key, cluster_name=None):
        """Override parent method for Ceph service providing charms.

        :param cluster_name: (Optional) Name of Ceph cluster to operate on.
                             Defaults to value of ``self.ceph_cluster_name``.
        :type cluster_name: str
        :raises: OSError
        """
        keyring_absolute_path = super().configure_ceph_keyring(
            key, cluster_name=cluster_name)
        if self.ceph_service_type != self.CephServiceType.client:
            return
        # If the service is a client-type sevice (sych as RBD Mirror) add
        # symlink to key in ``/etc/ceph``.
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


class PolicydOverridePlugin(object):
    """The PolicydOverridePlugin is provided to manage the policy.d overrides
    to charms.openstack charms.  It heavily leans on the
    charmhelpers.contrib.openstack.policyd to provide the functionality.  The
    methods provided in this class simply use the functions from charm-helpers
    so that charm authors can simply include this plugin class into the
    inheritance list of the charm class.

    It's very important that the PolicyOverridePlugin class appear FIRST in the
    list of classes when declaring the charm class.  This is to ensure that the
    config_changed() method in this class gets called first, and it then calls
    other classes.  Otherwise, the config_changed method in the base class will
    need to call the config_changed() method in this class manually.  e.g. from
    Designate:

        class DesignateCharm(ch_plugins.PolicydOverridePlugin,
                             openstack_charm.HAOpenStackCharm):

    Note that this feature is only available with OpenStack versions of
    'queens' and later, and Ubuntu versions of 'bionic' and later.  Prior to
    those versions, the feature will not activate.  This is checked in the
    charm-helpers policyd implementation functions which are called from this
    class' implementation.

    This should be read in conjunction with the module
    charmhelpers.contrib.openstack.policyd which provides further details on
    the changes that need to be made to a charm to enable this feature.

    Note that the metadata.yaml and config.yaml needs to be updated for the
    charm to actually be able to use this class.  See the
    charmhelpers.contrib.openstack.policyd module for further details.

    The following class variables are used to drive the plugin and should be
    declared on the class:

       policyd_service_name = str
       policyd_blacklist_paths = Union[None, List[str]]
       policyd_blacklist_keys = Union[None, List[str]]
       policyd_template_function = Union[None, Callable[[str], str]]
       policyd_restart_on_change = Union[None, bool]

    These have the following meanings:

    policyd_service_name:
        This is the name of the payload that is having an override.  e.g.
        keystone.  It is used to construct the policy.d directory:
        /etc/keystone/policy.d/

    policyd_blacklist_paths: (Optional)
        These are other policyd overrides that exist in the above directory
        that should not be touched.  It is a list of the FULL path.  e.g.
        /etc/keystone/policy.d/charm-overrides.yaml

    policyd_blacklist_keys: (Optional)
        These are keys that should not appear in the YAML files.  e.g. admin.

    policyd_template_function: (Optional)
        This is an callable that takes a string that returns another string
        that tis then loaded as the yaml file.  This is intended to allow a
        charm to modify the proposed yaml file to allow substitution of rules
        and values under the control of the charm.  The charm needs to supply
        the substitution function (and thus the variables that will be used).

    policyd_restart_on_change: Optional
        If set to True, then the service will be restarted using the charm
        class'  `restart_services` method.
    """

    def _policyd_function_args(self):
        """Returns the parameters that need to be passed to the charm-helpers
        policyd implemenation functions.

        :returns: ([openstack_release, payload_name],
                   {blacklist_paths=...,
                    blacklist_keys=...,
                    template_function=...,
                    restart_handler=...,})
        :rtype: Tuple[List[str,str], Dict[str,str]]
        """
        blacklist_paths = getattr(self, 'policyd_blacklist_paths', None)
        blacklist_keys = getattr(self, 'policyd_blacklist_keys', None)
        template_function = getattr(self, 'policyd_template_function', None)
        if getattr(self, 'policyd_restart_on_change', False):
            restart_handler = self.restart_services
        else:
            restart_handler = None
        return ([self.release, self.policyd_service_name],
                dict(blacklist_paths=blacklist_paths,
                     blacklist_keys=blacklist_keys,
                     template_function=template_function,
                     restart_handler=restart_handler))

    def _maybe_policyd_overrides(self):
        args, kwargs = self._policyd_function_args()
        ch_policyd.maybe_do_policyd_overrides(*args, **kwargs)

    def install(self):
        """Hook into the install"""
        super().install()
        self._maybe_policyd_overrides()

    def upgrade_charm(self):
        """Check the policyd during an upgrade_charm"""
        super().upgrade_charm()
        self._maybe_policyd_overrides()

    def config_changed(self):
        """Note that this is usually a nop, and is only called from the default
        handler.  Please check that the charm implementation actually uses it.
        """
        try:
            super().config_changed()
        except Exception:
            pass
        args, kwargs = self._policyd_function_args()
        ch_policyd.maybe_do_policyd_overrides_on_config_changed(
            *args, **kwargs)
