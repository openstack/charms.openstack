# Copyright 2016 Canonical Ltd
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

# OpenStackCharm() - base class for build OpenStack charms from for the
# reactive framework.

# need/want absolute imports for the package imports to work properly
from __future__ import absolute_import

import base64
import collections
import contextlib
import functools
import itertools
import os
import random
import re
import string
import subprocess

import apt_pkg as apt
import six

import charmhelpers.contrib.network.ip as ch_ip
import charmhelpers.contrib.openstack.templating as os_templating
import charmhelpers.contrib.openstack.utils as os_utils
import charmhelpers.core.hookenv as hookenv
import charmhelpers.core.host as ch_host
import charmhelpers.core.templating
import charmhelpers.core.unitdata as unitdata
import charmhelpers.fetch as fetch
import charms.reactive as reactive

import charms_openstack.ip as os_ip
import charms_openstack.adapters as os_adapters


# _releases{} is a dictionary of release -> class that is instantiated
# according to the the release that is being requested.  i.e. a charm can
# handle more than one release.  The OpenStackCharm() derived class sets the
# `release` variable to indicate which release that the charm supports.
# Any subsequent releases that need a different/specialised charm uses the
# `release` class property to indicate that it handles that release onwards.
_releases = {}

# `_singleton` stores the instance of the class that is being used during a
# hook invocation.
_singleton = None

# `_release_selector_function` holds a function that takes optionally takes a
# release and commutes it to another release or just returns a release.
# This is to enable the defining code to define which release is used.
_release_selector_function = None

# List of releases that OpenStackCharm based charms know about
KNOWN_RELEASES = [
    'diablo',
    'essex',
    'folsom',
    'grizzly',
    'havana',
    'icehouse',
    'juno',
    'kilo',
    'liberty',
    'mitaka',
    'newton',
]

VIP_KEY = "vip"
CIDR_KEY = "vip_cidr"
IFACE_KEY = "vip_iface"
APACHE_SSL_VHOST = '/etc/apache2/sites-available/openstack_https_frontend.conf'

OPENSTACK_RELEASE_KEY = 'charmers.openstack-release-version'

# handler support for default handlers

# The default handlers that charms.openstack provides.
ALLOWED_DEFAULT_HANDLERS = [
    'charm.installed',
    'amqp.connected',
    'shared-db.connected',
    'identity-service.connected',
    'identity-service.available',
    'config.changed',
    'charm.default-select-release',
    'update-status',
]

# Where to store the default handler functions for each default state
_default_handler_map = {}


def use_defaults(*defaults):
    """Activate the default functionality for various handlers

    This is to provide default functionality for common operations for
    openstack charms.
    """
    for state in defaults:
        if state in ALLOWED_DEFAULT_HANDLERS:
            if state in _default_handler_map:
                # Initialise the default handler for this state
                _default_handler_map[state]()
            else:
                raise RuntimeError(
                    "State '{}' is allowed, but has no handler???"
                    .format(state))
        else:
            raise RuntimeError("Default handler for '{}' doesn't exist"
                               .format(state))


def _map_default_handler(state):
    """Decorator to map a default handler to a state -- just makes adding
    handlers a bit easier.

    :param state: the state that the handler is for.
    :raises RuntimeError: if the state doesn't exist in
        ALLOWED_DEFAULT_HANDLERS
    """
    def wrapper(f):
        if state in _default_handler_map:
            raise RuntimeError(
                "State '{}' can't have more than one default handler"
                .format(state))
        if state not in ALLOWED_DEFAULT_HANDLERS:
            raise RuntimeError(
                "State '{} doesn't have a default handler????".format(state))
        _default_handler_map[state] = f
        return f
    return wrapper


@_map_default_handler('charm.installed')
def make_default_install_handler():

    @reactive.when_not('charm.installed')
    def default_install():
        """Provide a default install handler

        The instance automagically becomes the derived OpenStackCharm instance.
        The kv() key charmers.openstack-release-version' is used to cache the
        release being used for this charm.  It is determined by the
        default_select_release() function below, unless this is overriden by
        the charm author
        """
        unitdata.kv().unset(OPENSTACK_RELEASE_KEY)
        OpenStackCharm.singleton.install()
        reactive.set_state('charm.installed')


@_map_default_handler('charm.default-select-release')
def make_default_select_release_handler():
    """This handler is a bit more unusual, as it just sets the release selector
    using the @register_os_release_selector decorator
    """

    @register_os_release_selector
    def default_select_release():
        """Determine the release based on the python-keystonemiddleware that is
        installed.

        Note that this function caches the release after the first install so
        that it doesn't need to keep going and getting it from the package
        information.
        """
        release_version = unitdata.kv().get(OPENSTACK_RELEASE_KEY, None)
        if release_version is None:
            release_version = os_utils.os_release('python-keystonemiddleware')
            unitdata.kv().set(OPENSTACK_RELEASE_KEY, release_version)
        return release_version


@_map_default_handler('amqp.connected')
def make_default_amqp_connection_handler():

    @reactive.when('amqp.connected')
    def default_amqp_connection(amqp):
        """Handle the default amqp connection.

        This requires that the charm implements get_amqp_credentials() to
        provide a tuple of the (user, vhost) for the amqp server
        """
        instance = OpenStackCharm.singleton
        user, vhost = instance.get_amqp_credentials()
        amqp.request_access(username=user, vhost=vhost)
        instance.assess_status()


@_map_default_handler('shared-db.connected')
def make_default_setup_database_handler():

    @reactive.when('shared-db.connected')
    def default_setup_database(database):
        """Handle the default database connection setup

        This requires that the charm implements get_database_setup() to provide
        a list of dictionaries;
        [{'database': ..., 'username': ..., 'hostname': ..., 'prefix': ...}]

        The prefix can be missing: it defaults to None.
        """
        instance = OpenStackCharm.singleton
        for db in instance.get_database_setup():
            database.configure(**db)
        instance.assess_status()


@_map_default_handler('identity-service.connected')
def make_default_setup_endpoint_connection():

    @reactive.when('identity-service.connected')
    def default_setup_endpoint_connection(keystone):
        """When the keystone interface connects, register this unit into the
        catalog.  This is the default handler, and calls on the charm class to
        provide the endpoint information.  If multiple endpoints are needed,
        then a custom endpoint handler will be needed.
        """
        instance = OpenStackCharm.singleton
        keystone.register_endpoints(instance.service_type,
                                    instance.region,
                                    instance.public_url,
                                    instance.internal_url,
                                    instance.admin_url)
        instance.assess_status()


@_map_default_handler('identity-service.available')
def make_setup_endpoint_available_handler():

    @reactive.when('identity-service.available')
    def default_setup_endpoint_available(keystone):
        """When the identity-service interface is available, this default
        handler switches on the SSL support.
        """
        instance = OpenStackCharm.singleton
        instance.configure_ssl(keystone)
        instance.assess_status()


@_map_default_handler('config.changed')
def make_default_config_changed_handler():

    @reactive.when('config.changed')
    def default_config_changed():
        """Default handler for config.changed state from reactive.  Just see if
        our status has changed.  This is just to clear any errors that may have
        got stuck due to missing async handlers, etc.
        """
        OpenStackCharm.singleton.assess_status()


def default_render_configs(*interfaces):
    """Default renderer for configurations.  Really just a proxy for
    OpenstackCharm.singleton.render_configs(..) with a call to update the
    workload status afterwards.

    :params *interfaces: the list of interfaces to provide to the
        render_configs() function
    """
    instance = OpenStackCharm.singleton
    instance.render_configs(interfaces)
    instance.assess_status()


@_map_default_handler('update-status')
def make_default_update_status_handler():

    @reactive.hook('update-status')
    def default_update_status():
        """Default handler for update-status state.
        Just call update status.
        """
        OpenStackCharm.singleton.assess_status()


# End of default handlers

def optional_interfaces(args, *interfaces):
    """Return a tuple with possible optional interfaces

    :param args: a list of reactive interfaces
    :param *interfaces: list of strings representing possible reactive
        interfaces.
    :returns: [list of reactive interfaces]
    """
    return args + tuple(ri for ri in (reactive.RelationBase.from_state(i)
                                      for i in interfaces)
                        if ri is not None)


# Note that we are breaking the camalcase rule as this is acting as a
# decoarator and a context manager, neither of which are expecting a 'class'
class provide_charm_instance(object):
    """Be a decoarator and a context manager at the same time to be able to
    easily provide the charm instance to some code that needs it.

    Allows the charm author to either write:

        @provide_charm_instance
        def some_handler(charm_instance, *args):
            charm_instance.method_call(*args)

    or:

        with provide_charm_instance() as charm_instance:
            charm_instance.some_method()
    """

    def __init__(self, f=None):
        self.f = f
        if f:
            functools.update_wrapper(self, f)

    def __call__(self, *args, **kwargs):
        return self.f(OpenStackCharm.singleton, *args, **kwargs)

    def __enter__(self):
        """with statement as gets the charm instance"""
        return OpenStackCharm.singleton

    def __exit__(self, *_):
        # Never bother with the exception
        return False


# Start of charm definitions

def get_charm_instance(release=None, *args, **kwargs):
    """Get an instance of the charm based on the release (or use the
    default if release is None).

    OS releases are in alphabetical order, so it looks for the first release
    that is provided if release is None, otherwise it finds the release that is
    before or equal to the release passed.

    Note that it passes args and kwargs to the class __init__() method.

    :param release: lc string representing release wanted.
    :returns: OpenStackCharm() derived class according to cls.releases
    """
    if len(_releases.keys()) == 0:
        raise RuntimeError("No derived OpenStackCharm() classes registered")
    # Note that this relies on OS releases being in alphabetica order
    known_releases = sorted(_releases.keys())
    cls = None
    if release is None:
        # take the latest version of the charm if no release is passed.
        cls = _releases[known_releases[-1]]
    else:
        # check that the release is a valid release
        if release not in KNOWN_RELEASES:
            raise RuntimeError(
                "Release {} is not a known OpenStack release?".format(release))
        release_index = KNOWN_RELEASES.index(release)
        if release_index < KNOWN_RELEASES.index(known_releases[0]):
            raise RuntimeError(
                "Release {} is not supported by this charm. Earliest support "
                "is {} release".format(release, known_releases[0]))
        else:
            # try to find the release that is supported.
            for known_release in reversed(known_releases):
                if release_index >= KNOWN_RELEASES.index(known_release):
                    cls = _releases[known_release]
                    break
    if cls is None:
        raise RuntimeError("Release {} is not supported".format(release))
    return cls(release=release, *args, **kwargs)


def register_os_release_selector(f):
    """Register a function that determines what the release is for the
    invocation run.  This allows the charm to define HOW the release is
    determined.

    Usage:

        @register_os_release_selector
        def my_release_selector():
            return os_release_chooser()

    The function should return a string which is an OS release.
    """
    global _release_selector_function
    if _release_selector_function is None:
        # we can only do this once in a system invocation.
        _release_selector_function = f
    else:
        raise RuntimeError(
            "Only a single release_selector_function is supported."
            " Called with {}".format(f.__name__))
    return f


class OpenStackCharmMeta(type):
    """Metaclass to provide a classproperty of 'singleton' so that class
    methods in the derived OpenStackCharm() class can simply use cls.singleton
    to get the instance of the charm.

    Thus cls.singleton is a singleton for accessing and creating the default
    OpenStackCharm() derived class.  This is to avoid a lot of boilerplate in
    the classmethods for the charm code.  This is because, usually, a
    classmethod is only called once per invocation of the script.

    Thus in the derived charm code we can do this:

        cls.singleton.instance_method(...)

    and this will instatiate the charm and call instance_method() on it.

    Note that self.singleton is also defined as a property for completeness so
    that cls.singleton and self.singleton give consistent results.
    """

    def __init__(cls, name, mro, members):
        """Receive the OpenStackCharm() (derived) class and store the release
        that it works against.  Each class defines a 'release' that it handles
        and the order of releases (as given in charmhelpers) determines (for
        any release) which OpenStackCharm() derived class is the handler for
        that class.  Note, that if the `name` is 'OpenStackCharm' then the
        function ignores the release, etc.

        :param name: string for class name.
        :param mro: tuple of base classes.
        :param members: dictionary of name to class attribute (f, p, a, etc.)
        """
        global _releases
        # Do not attempt to calculate the release for an abstract class
        if members.get('abstract_class', False):
            return
        if 'release' in members.keys():
            release = members['release']
            if release not in KNOWN_RELEASES:
                raise RuntimeError(
                    "Release {} is not a known OpenStack release"
                    .format(release))
            if release in _releases.keys():
                raise RuntimeError(
                    "Release {} defined more than once in classes {} and {} "
                    " (at least)"
                    .format(release, _releases[release].__name__, name))
            # store the class against the release.
            _releases[release] = cls
        else:
            raise RuntimeError(
                "class '{}' does not define a release that it supports. "
                "Please use the 'release' class property to define the "
                "release.".format(name))

    @property
    def singleton(cls):
        """Either returns the already created charm, or create a new one.

        This uses the _release_selector_function to choose the release is one
        has been registered, otherwise None is passed to get_charm_instance()
        """
        global _singleton
        if _singleton is None:
            release = None
            # see if a _release_selector_function has been registered.
            if _release_selector_function is not None:
                release = _release_selector_function()
            _singleton = get_charm_instance(release=release)
        return _singleton


@six.add_metaclass(OpenStackCharmMeta)
class OpenStackCharm(object):
    """
    Base class for all OpenStack Charm classes;
    encapulates general OpenStack charm payload operations

    Theory:
    Derive form this class, set the name, first_release and releases class
    variables so that get_charm_instance() will create an instance of this
    charm.

    See the other class variables for details on what they are for and do.
    """

    abstract_class = True

    # first_release = this is the first release in which this charm works
    release = 'icehouse'

    # The name of the charm (for printing, etc.)
    name = 'charmname'

    # List of packages to install
    packages = []

    # Package to determine application version from
    # defaults to first in packages if not provided
    version_package = None

    # Dictionary mapping services to ports for public, admin and
    # internal endpoints
    api_ports = {}

    # Keystone endpoint type
    service_type = None

    # Default service for the charm
    default_service = None

    # A dictionary of:
    # {
    #    'config.file': ['list', 'of', 'services', 'to', 'restart'],
    #    'config2.file': ['more', 'services'],
    # }
    restart_map = {}

    # The list of required services that are checked for assess_status
    # e.g. required_relations = ['identity-service', 'shared-db']
    required_relations = []

    # The command used to sync the database
    sync_cmd = []

    # The list of services that this charm manages
    services = []

    # The adapters class that this charm uses to adapt interfaces.
    # If None, then it defaults to OpenstackRelationsAdapter
    adapters_class = os_adapters.OpenStackRelationAdapters

    # The configuration base class to use for the charm
    # If None, then the default ConfigurationAdapter is used.
    configuration_class = os_adapters.ConfigurationAdapter

    ha_resources = []
    adapters_class = None
    HAPROXY_CONF = '/etc/haproxy/haproxy.cfg'
    package_codenames = {}

    @property
    def singleton(self):
        """Return the only instance of the charm class in this run"""
        # Note refers back to the Metaclass property for this charm.
        return self.__class__.singleton

    def __init__(self, interfaces=None, config=None, release=None):
        """Instantiate an instance of the class.

        Sets up self.config and self.adapter_instance if cls.adapters_class and
        interfaces has been set.

        :param interfaces: list of interface instances for the charm.
        :param config: the config for the charm (optionally None for
            automatically using config())
        """
        self.config = config or hookenv.config()
        self.release = release
        self.adapters_instance = None
        if interfaces and self.adapters_class:
            self.adapters_instance = self.adapters_class(interfaces,
                                                         charm_instance=self)

    @property
    def all_packages(self):
        """List of packages to be installed

        @return ['pkg1', 'pkg2', ...]
        """
        return self.packages

    @property
    def full_restart_map(self):
        """Map of services to be restarted if a file changes

        @return {
                    'file1': ['svc1', 'svc3'],
                    'file2': ['svc2', 'svc3'],
                    ...
                }
        """
        return self.restart_map

    def install(self):
        """Install packages related to this charm based on
        contents of self.packages attribute.
        """
        packages = fetch.filter_installed_packages(
            self.all_packages)
        if packages:
            hookenv.status_set('maintenance', 'Installing packages')
            fetch.apt_install(packages, fatal=True)
        self.set_state('{}-installed'.format(self.name))
        hookenv.status_set('maintenance',
                           'Installation complete - awaiting next status')

    def set_state(self, state, value=None):
        """proxy for charms.reactive.bus.set_state()"""
        reactive.bus.set_state(state, value)

    def remove_state(self, state):
        """proxy for charms.reactive.bus.remove_state()"""
        reactive.bus.remove_state(state)

    def get_state(self, state):
        """proxy for charms.reactive.bus.get_state()"""
        return reactive.bus.get_state(state)

    def api_port(self, service, endpoint_type=os_ip.PUBLIC):
        """Return the API port for a particular endpoint type from the
        self.api_ports{}.

        :param service: string for service name
        :param endpoing_type: one of charm.openstack.ip.PUBLIC| INTERNAL| ADMIN
        :returns: port (int)
        """
        return self.api_ports[service][endpoint_type]

    def configure_source(self):
        """Configure installation source using the config item
        'openstack-origin'

        This configures the installation source for deb packages and then
        updates the packages list on the unit.
        """
        os_utils.configure_installation_source(self.config['openstack-origin'])
        fetch.apt_update(fatal=True)

    @property
    def region(self):
        """Return the OpenStack Region as contained in the config item 'region'
        """
        return self.config['region']

    @property
    def public_url(self):
        """Return the public endpoint URL for the default service as specified
        in the self.default_service attribute
        """
        return "{}:{}".format(os_ip.canonical_url(os_ip.PUBLIC),
                              self.api_port(self.default_service,
                                            os_ip.PUBLIC))

    @property
    def admin_url(self):
        """Return the admin endpoint URL for the default service as specificed
        in the self.default_service attribute
        """
        return "{}:{}".format(os_ip.canonical_url(os_ip.ADMIN),
                              self.api_port(self.default_service,
                                            os_ip.ADMIN))

    @property
    def internal_url(self):
        """Return the internal internal endpoint URL for the default service as
        specificated in the self.default_service attribtue
        """
        return "{}:{}".format(os_ip.canonical_url(os_ip.INTERNAL),
                              self.api_port(self.default_service,
                                            os_ip.INTERNAL))

    @property
    def application_version(self):
        """Return the current version of the application being deployed by
        the charm, as indicated by the version_package attribute
        """
        if not self.version_package:
            self.version_package = self.packages[0]
        version = get_upstream_version(
            self.version_package
        )
        if not version:
            version = os_utils.os_release(self.version_package)
        return version

    @contextlib.contextmanager
    def restart_on_change(self):
        """Restart the services in the self.restart_map{} attribute if any of
        the files identified by the keys changes for the wrapped call.

        This function is a @decorator that checks if the wrapped function
        changes any of the files identified by the keys in the
        self.restart_map{} and, if they change, restarts the services in the
        corresponding list.
        """
        checksums = {path: ch_host.path_hash(path)
                     for path in self.full_restart_map.keys()}
        yield
        restarts = []
        for path in self.full_restart_map:
            if ch_host.path_hash(path) != checksums[path]:
                restarts += self.full_restart_map[path]
        services_list = list(collections.OrderedDict.fromkeys(restarts).keys())
        for service_name in services_list:
            ch_host.service_stop(service_name)
        for service_name in services_list:
            ch_host.service_start(service_name)

    def render_all_configs(self, adapters_instance=None):
        """Render (write) all of the config files identified as the keys in the
        self.restart_map{}

        Note: If the config file changes on storage as a result of the config
        file being written, then the services are restarted as per
        the restart_the_services() method.

        If adapters_instance is None then the self.adapters_instance is used
        that was setup in the __init__() method.

        :param adapters_instance: [optional] the adapters_instance to use.
        """
        self.render_configs(self.full_restart_map.keys(),
                            adapters_instance=adapters_instance)

    def render_configs(self, configs, adapters_instance=None):
        """Render the configuration files identified in the list passed as
        configs.

        If adapters_instance is None then the self.adapters_instance is used
        that was setup in the __init__() method.

        :param configs: list of strings, the names of the configuration files.
        :param adapters_instance: [optional] the adapters_instance to use.
        """
        if adapters_instance is None:
            adapters_instance = self.adapters_instance
        with self.restart_on_change():
            for conf in configs:
                charmhelpers.core.templating.render(
                    source=os.path.basename(conf),
                    template_loader=os_templating.get_loader(
                        'templates/', self.release),
                    target=conf,
                    context=adapters_instance)

    def render_with_interfaces(self, interfaces, configs=None):
        """Render the configs using the interfaces passed; overrides any
        interfaces passed in the instance creation.

        :param interfaces: list of interface objects to render against
        """
        if not configs:
            configs = self.full_restart_map.keys()
        # Maintain compatability with exisiting adapter classes which have
        # not implemented the charm_instance arg Bug #1623917
        try:
            self.render_configs(
                configs,
                adapters_instance=self.adapters_class(interfaces,
                                                      charm_instance=self))
        except TypeError:
            self.render_configs(
                configs,
                adapters_instance=self.adapters_class(interfaces))

    def restart_all(self):
        """Restart all the services configured in the self.services[]
        attribute.
        """
        for svc in self.services:
            ch_host.service_restart(svc)

    def db_sync_done(self):
        return hookenv.leader_get(attribute='db-sync-done')

    def db_sync(self):
        """Perform a database sync using the command defined in the
        self.sync_cmd attribute. The services defined in self.services are
        restarted after the database sync.
        """
        if not self.db_sync_done() and hookenv.is_leader():
            subprocess.check_call(self.sync_cmd)
            hookenv.leader_set({'db-sync-done': True})
            # Restart services immediately after db sync as
            # render_domain_config needs a working system
            self.restart_all()

    def assess_status(self):
        """Assess the status of the unit and set the status and a useful
        message as appropriate.

        The 3 checks are:

         1. Check if the unit has been paused (using
            os_utils.is_unit_paused_set().
         2. Check if the interfaces are all present (using the states that are
            set by each interface as it comes 'live'.
         3. Do a custom_assess_status_check() check.
         4. Check that services that should be running are running.

        Each sub-function determins what checks are taking place.

        If custom assess_status() functionality is required then the derived
        class should override any of the 4 check functions to alter the
        behaviour as required.

        Note that if ports are NOT to be checked, then the derived class should
        override :meth:`ports_to_check()` and return an empty list.

        SIDE EFFECT: this function calls status_set(state, message) to set the
        workload status in juju and calls application_version_set(vers) to set
        the application version in juju.
        """
        hookenv.application_version_set(self.application_version)
        for f in [self.check_if_paused,
                  self.check_interfaces,
                  self.custom_assess_status_check,
                  self.check_services_running]:
            state, message = f()
            if state is not None:
                hookenv.status_set(state, message)
                return
        # No state was particularly set, so assume the unit is active
        hookenv.status_set('active', 'Unit is ready')

    def custom_assess_status_check(self):
        """Override this function in a derived class if there are any other
        status checks that need to be done that aren't about relations, etc.

        Return (None, None) if the status is okay (i.e. the unit is active).
        Return ('active', message) do shortcut and force the unit to the active
        status.
        Return (other_status, message) to set the status to desired state.

        :returns: None, None - no action in this function.
        """
        return None, None

    def check_if_paused(self):
        """Check if the unit is paused and return either the paused status,
        message or None, None if the unit is not paused.  If the unit is paused
        but a service is incorrectly running, then the function returns a
        broken status.

        :returns: (status, message) or (None, None)
        """
        return os_utils._ows_check_if_paused(
            services=self.services,
            ports=self.ports_to_check(self.api_ports))

    def check_interfaces(self):
        """Check that the required interfaces have both connected and availble
        states set.

        This requires a convention from the OS interfaces that they set the
        '{relation_name}.connected' state on connection, and the
        '{relation_name}.available' state when the connection information is
        available and the interface is ready to go.

        The interfaces (relations) that are checked are named in
        self.required_relations which is a list of strings representing the
        generic relation name.  e.g. 'identity-service' rather than 'keystone'.

        Returns (None, None) if the interfaces are okay, or a status, message
        if any of the interfaces are not ready.

        Derived classes can augment/alter the checks done by overriding the
        companion method :property:`states_to_check` which converts a relation
        into the states to confirm existence, along with the error message.

        :returns (status, message) or (None, None)
        """
        states_to_check = self.states_to_check()
        # bail if there is nothing to do.
        if not states_to_check:
            return None, None
        available_states = reactive.bus.get_states().keys()
        status = None
        messages = []
        for relation, states in six.iteritems(states_to_check):
            for state, err_status, err_msg in states:
                if state not in available_states:
                    messages.append(err_msg)
                    status = os_utils.workload_state_compare(status,
                                                             err_status)
                    # as soon as we error on a relation, skip to the next one.
                    break
        if status is not None:
            return status, ", ".join(messages)
        # Everything is fine.
        return None, None

    def states_to_check(self, required_relations=None):
        """Construct a default set of connected and available states for each
        of the relations passed, along with error messages and new status
        conditions if they are missing.

        The method returns a {relation: [(state, err_status, err_msg), (...),]}
        This corresponds to the relation, the state to check for, the error
        status to set if that state is missing, and the message to show if the
        state is missing.

        The list of tuples is evaulated in order for each relation, and stops
        after the first failure.  This means that it doesn't check (say)
        available if connected is not available.

        :param required_relations: (default None) - override self.relations
        :returns: {relation: [(state, err_status, err_msg), (...),]}
        """
        states_to_check = collections.OrderedDict()
        if required_relations is None:
            required_relations = self.required_relations
        for relation in required_relations:
            states_to_check[relation] = [
                ("{}.connected".format(relation),
                 "blocked",
                 "'{}' missing".format(relation)),
                ("{}.available".format(relation),
                 "waiting",
                 "'{}' incomplete".format(relation))]
        return states_to_check

    def check_services_running(self):
        """Check that the services that should be running are actually running.

        This uses the self.services and self.api_ports to determine what should
        be checked.

        :returns: (status, message) or (None, None).
        """
        # This returns either a None, None or a status, message if the service
        # is not running or the ports are not open.
        return os_utils._ows_check_services_running(
            services=self.services,
            ports=self.ports_to_check(self.api_ports))

    def ports_to_check(self, ports):
        """Return a flattened, sorted, unique list of ports from self.api_ports

        NOTE. To disable port checking, simply override this method in the
        derived class and return an empty [].

        :param ports: {key: {subkey: value}}
        :returns: [value1, value2, ...]
        """
        # NB self.api_ports = {key: {space: value}}
        # The chain .. map  flattens all the values into a single list
        return sorted(set(itertools.chain(*map(lambda x: x.values(),
                                               ports.values()))))

    @staticmethod
    def get_os_codename_package(package, codenames, fatal=True):
        """Derive OpenStack release codename from an installed package.

        :param package: str Package name to lookup in apt cache
        :param codenames: dict of OrderedDict eg
            {
             'pkg1': collections.OrderedDict([
                 ('2', 'mitaka'),
                 ('3', 'newton'),
                 ('4', 'ocata'), ]),
             'pkg2': collections.OrderedDict([
                 ('12.6', 'mitaka'),
                 ('13.2', 'newton'),
                 ('14.7', 'ocata'), ]),
            }
        :param fatal: bool Raise exception if pkg not installed
        :returns: str OpenStack version name corresponding to package
        """
        cache = fetch.apt_cache()

        try:
            pkg = cache[package]
        except KeyError:
            if not fatal:
                return None
            # the package is unknown to the current apt cache.
            e = ('Could not determine version of package with no installation '
                 'candidate: {}'.format(package))
            raise Exception(e)
        if not pkg.current_ver:
            if not fatal:
                return None

        vers = apt.upstream_version(pkg.current_ver.ver_str)
        # x.y match only for 20XX.X
        # and ignore patch level for other packages
        match = re.match('^(\d+)\.(\d+)', vers)

        if match:
            vers = match.group(0)

        # Generate a major version number for newer semantic
        # versions of openstack projects
        major_vers = vers.split('.')[0]
        if (package in codenames and
                major_vers in codenames[package]):
            return codenames[package][major_vers]

    def get_os_version_package(self, package, fatal=True):
        """Derive OpenStack version number from an installed package.

        :param package: str Package name to lookup in apt cache
        :param fatal: bool Raise exception if pkg not installed
        :returns: str OpenStack version number corresponding to package
        """
        codenames = self.package_codenames or os_utils.PACKAGE_CODENAMES
        codename = self.get_os_codename_package(
            package, codenames, fatal=fatal)
        if not codename:
            return None

        vers_map = os_utils.OPENSTACK_CODENAMES
        for version, cname in six.iteritems(vers_map):
            if cname == codename:
                return version

    def openstack_upgrade_available(self, package=None):
        """Check if an OpenStack upgrade is available

        :param package: str Package name to use to check upgrade availability
        :returns: bool
        """
        if not package:
            package = self.release_pkg

        src = self.config['openstack-origin']
        cur_vers = self.get_os_version_package(package)
        avail_vers = os_utils.get_os_version_install_source(src)
        apt.init()
        return apt.version_compare(avail_vers, cur_vers) == 1

    def upgrade_if_available(self, interfaces_list):
        """Upgrade OpenStack if an upgrade is available

        :param interfaces_list: List of instances of interface classes
        :returns: None
        """
        if self.openstack_upgrade_available(self.release_pkg):
            hookenv.status_set('maintenance', 'Running openstack upgrade')
            self.do_openstack_pkg_upgrade()
            self.do_openstack_upgrade_config_render(interfaces_list)
            self.do_openstack_upgrade_db_migration()

    def do_openstack_pkg_upgrade(self):
        """Upgrade OpenStack packages

        :returns: None
        """
        new_src = self.config['openstack-origin']
        new_os_rel = os_utils.get_os_codename_install_source(new_src)
        hookenv.log('Performing OpenStack upgrade to %s.' % (new_os_rel))

        os_utils.configure_installation_source(new_src)
        fetch.apt_update()

        dpkg_opts = [
            '--option', 'Dpkg::Options::=--force-confnew',
            '--option', 'Dpkg::Options::=--force-confdef',
        ]
        fetch.apt_upgrade(
            options=dpkg_opts,
            fatal=True,
            dist=True)
        fetch.apt_install(
            packages=self.all_packages,
            options=dpkg_opts,
            fatal=True)
        self.release = new_os_rel

    def do_openstack_upgrade_config_render(self, interfaces_list):
        """Render configs after upgrade

        :returns: None
        """
        self.render_with_interfaces(interfaces_list)

    def do_openstack_upgrade_db_migration(self):
        """Run database migration after upgrade

        :returns: None
        """
        if hookenv.is_leader():
            subprocess.check_call(self.sync_cmd)
        else:
            hookenv.log("Deferring DB sync to leader", level=hookenv.INFO)


class OpenStackAPICharm(OpenStackCharm):
    """The base class for API OS charms -- this just bakes in the default
    configuration and adapter classes.
    """
    abstract_class = True

    # The adapters class that this charm uses to adapt interfaces.
    # If None, then it defaults to OpenstackRelationAdapters
    adapters_class = os_adapters.OpenStackAPIRelationAdapters

    # The configuration base class to use for the charm
    # If None, then the default ConfigurationAdapter is used.
    configuration_class = os_adapters.APIConfigurationAdapter

    def install(self):
        """Install packages related to this charm based on
        contents of self.packages attribute.
        """
        self.configure_source()
        super(OpenStackAPICharm, self).install()

    def get_amqp_credentials(self):
        """Provide the default amqp username and vhost as a tuple.

        This needs to be overriden in a derived class to provide the username
        and vhost to the amqp interface IF the default amqp handlers are being
        used.
        :returns (username, host): two strings to send to the amqp provider.
        """
        raise RuntimeError(
            "get_amqp_credentials() needs to be overriden in the derived "
            "class")

    def get_database_setup(self):
        """Provide the default database credentials as a list of 3-tuples

        This is used when using the default handlers for the shared-db service
        and provides the (db, db_user, ip) for each database as a list.

        returns a structure of:
        [
            {'database': <database>,
             'username': <username>,
             'hostname': <hostname of this unit>
             'prefix': <the optional prefix for the database>, },
        ]

        This allows multiple databases to be setup.

        If more complex database setup is required, then the default
        setup_database() will need to be ignored, and a custom function
        written.

        :returns [{'database': ...}, ...]: credentials for multiple databases
        """
        raise RuntimeError(
            "get_database_setup() needs to be overriden in the derived "
            "class")


class HAOpenStackCharm(OpenStackAPICharm):

    abstract_class = True

    def __init__(self, **kwargs):
        super(HAOpenStackCharm, self).__init__(**kwargs)
        self.set_haproxy_stat_password()
        self.set_config_defined_certs_and_keys()

    @property
    def apache_vhost_file(self):
        """Apache vhost for SSL termination

        :returns: string
        """
        return APACHE_SSL_VHOST

    def enable_apache_ssl_vhost(self):
        """Enable Apache vhost for SSL termination

        Enable Apache vhost for SSL termination if vhost exists and it is not
        curently enabled
        """
        if os.path.exists(self.apache_vhost_file):
            check_enabled = subprocess.call(
                ['a2query', '-s', 'openstack_https_frontend'])
            if check_enabled != 0:
                subprocess.check_call(['a2ensite', 'openstack_https_frontend'])
                ch_host.service_reload('apache2', restart_on_failure=True)

    def configure_apache(self):
        if self.apache_enabled():
            self.install()
            self.enable_apache_modules()
            self.enable_apache_ssl_vhost()

    @property
    def all_packages(self):
        """List of packages to be installed

        @return ['pkg1', 'pkg2', ...]
        """
        _packages = self.packages[:]
        if self.haproxy_enabled():
            _packages.append('haproxy')
        if self.apache_enabled():
            _packages.append('apache2')
        return _packages

    @property
    def full_restart_map(self):
        """Map of services to be restarted if a file changes

        @return {
                    'file1': ['svc1', 'svc3'],
                    'file2': ['svc2', 'svc3'],
                    ...
                }
        """
        _restart_map = self.restart_map.copy()
        if self.haproxy_enabled():
            _restart_map[self.HAPROXY_CONF] = ['haproxy']
        if self.apache_enabled():
            _restart_map[self.apache_vhost_file] = ['apache2']
        return _restart_map

    def apache_enabled(self):
        """Determine if apache is being used

        @return True if apache is being used"""
        return self.get_state('ssl.enabled')

    def haproxy_enabled(self):
        """Determine if haproxy is fronting the services

        @return True if haproxy is fronting the service"""
        return 'haproxy' in self.ha_resources

    def configure_ha_resources(self, hacluster):
        """Inform the ha subordinate about each service it should manage. The
        child class specifies the services via self.ha_resources

        @param hacluster instance of interface class HAClusterRequires
        """
        RESOURCE_TYPES = {
            'vips': self._add_ha_vips_config,
            'haproxy': self._add_ha_haproxy_config,
        }
        if self.ha_resources:
            for res_type in self.ha_resources:
                RESOURCE_TYPES[res_type](hacluster)
            hacluster.bind_resources(iface=self.config[IFACE_KEY])

    def _add_ha_vips_config(self, hacluster):
        """Add a VirtualIP object for each user specified vip to self.resources

        @param hacluster instance of interface class HAClusterRequires
        """
        for vip in self.config.get(VIP_KEY, '').split():
            iface = (ch_ip.get_iface_for_address(vip) or
                     self.config.get(IFACE_KEY))
            netmask = (ch_ip.get_netmask_for_address(vip) or
                       self.config.get(CIDR_KEY))
            if iface is not None:
                hacluster.add_vip(self.name, vip, iface, netmask)

    def _add_ha_haproxy_config(self, hacluster):
        """Add a InitService object for haproxy to self.resources

        @param hacluster instance of interface class HAClusterRequires
        """
        hacluster.add_init_service(self.name, 'haproxy')

    def set_haproxy_stat_password(self):
        """Set a stats password for accessing haproxy statistics"""
        if not self.get_state('haproxy.stat.password'):
            password = ''.join([
                random.choice(string.ascii_letters + string.digits)
                for n in range(32)])
            self.set_state('haproxy.stat.password', password)

    def enable_apache_modules(self):
        """Enable Apache modules needed for SSL termination"""
        restart = False
        for module in ['ssl', 'proxy', 'proxy_http']:
            check_enabled = subprocess.call(['a2query', '-m', module])
            if check_enabled != 0:
                subprocess.check_call(['a2enmod', module])
                restart = True
        if restart:
            ch_host.service_restart('apache2')

    def configure_cert(self, cert, key, cn=None):
        """Configure service SSL cert and key

        Write out service SSL certificate and key for Apache.

        @param cert string SSL Certificate
        @param key string SSL Key
        @param cn string Canonical name for service
        """
        if not cn:
            cn = os_ip.resolve_address(endpoint_type=os_ip.INTERNAL)
        ssl_dir = os.path.join('/etc/apache2/ssl/', self.name)
        ch_host.mkdir(path=ssl_dir)
        if cn:
            cert_filename = 'cert_{}'.format(cn)
            key_filename = 'key_{}'.format(cn)
        else:
            cert_filename = 'cert'
            key_filename = 'key'

        ch_host.write_file(path=os.path.join(ssl_dir, cert_filename),
                           content=cert.encode('utf-8'))
        ch_host.write_file(path=os.path.join(ssl_dir, key_filename),
                           content=key.encode('utf-8'))

    def get_local_addresses(self):
        """Return list of local addresses on each configured network

        For each network return an address the local unit has on that network
        if one exists.

        @returns [private_addr, admin_addr, public_addr, ...]
        """
        addresses = [
            os_utils.get_host_ip(hookenv.unit_get('private-address'))]
        for addr_type in os_ip.ADDRESS_MAP.keys():
            laddr = os_ip.resolve_address(endpoint_type=addr_type)
            if laddr:
                addresses.append(laddr)
        return sorted(list(set(addresses)))

    def get_certs_and_keys(self, keystone_interface=None):
        """Collect SSL config for local endpoints

        SSL keys and certs may come from user specified configuration for this
        charm or they may come directly from Keystone.

        If collecting from keystone there may be a certificate and key per
        endpoint (public, admin etc).

        @returns [
            {'key': 'key1', 'cert': 'cert1', 'ca': 'ca1', 'cn': 'cn1'}
            {'key': 'key2', 'cert': 'cert2', 'ca': 'ca2', 'cn': 'cn2'}
            ...
        ]
        """
        if self.config_defined_ssl_key and self.config_defined_ssl_cert:
            return [{
                'key': self.config_defined_ssl_key.decode('utf-8'),
                'cert': self.config_defined_ssl_cert.decode('utf-8'),
                'ca': self.config_defined_ssl_ca.decode('utf-8'),
                'cn': None}]
        elif keystone_interface:
            keys_and_certs = []
            for addr in self.get_local_addresses():
                key = keystone_interface.get_ssl_key(addr)
                cert = keystone_interface.get_ssl_cert(addr)
                ca = keystone_interface.get_ssl_ca()
                if key and cert:
                    keys_and_certs.append({
                        'key': key,
                        'cert': cert,
                        'ca': ca,
                        'cn': addr})
            return keys_and_certs
        else:
            return []

    def set_config_defined_certs_and_keys(self):
        """Set class attributes for user defined ssl options

        Inspect user defined SSL config and set
        config_defined_{ssl_key, ssl_cert, ssl_ca}
        """
        for ssl_param in ['ssl_key', 'ssl_cert', 'ssl_ca']:
            key = 'config_defined_{}'.format(ssl_param)
            if self.config.get(ssl_param):
                setattr(self, key,
                        base64.b64decode(self.config.get(ssl_param)))
            else:
                setattr(self, key, None)

    @property
    def rabbit_client_cert_dir(self):
        return '/var/lib/charm/{}'.format(hookenv.service_name())

    @property
    def rabbit_cert_file(self):
        return '{}/rabbit-client-ca.pem'.format(self.rabbit_client_cert_dir)

    def configure_ssl(self, keystone_interface=None):
        """Configure SSL certificates and keys

        @param keystone_interface KeystoneRequires class
        """
        keystone_interface = (reactive.RelationBase.from_state(
            'identity-service.available.ssl') or
            reactive.RelationBase.from_state(
                'identity-service.available.ssl_legacy'))
        ssl_objects = self.get_certs_and_keys(
            keystone_interface=keystone_interface)
        if ssl_objects:
            for ssl in ssl_objects:
                self.configure_cert(ssl['cert'], ssl['key'], cn=ssl['cn'])
                self.configure_ca(ssl['ca'])
            self.set_state('ssl.enabled', True)
            self.configure_apache()
        else:
            self.set_state('ssl.enabled', False)
        amqp_ssl = reactive.RelationBase.from_state('amqp.available.ssl')
        if amqp_ssl:
            self.configure_rabbit_cert(amqp_ssl)

    def configure_rabbit_cert(self, rabbit_interface):
        if not os.path.exists(self.rabbit_client_cert_dir):
            os.makedirs(self.rabbit_client_cert_dir)
        with open(self.rabbit_cert_file, 'w') as crt:
            crt.write(rabbit_interface.get_ssl_cert())

    @contextlib.contextmanager
    def update_central_cacerts(self, cert_files, update_certs=True):
        """Update Central certs info if once of cert_files changes"""
        checksums = {path: ch_host.path_hash(path)
                     for path in cert_files}
        yield
        new_checksums = {path: ch_host.path_hash(path)
                         for path in cert_files}
        if checksums != new_checksums and update_certs:
            self.run_update_certs()

    def configure_ca(self, ca_cert, update_certs=True):
        """Write Certificate Authority certificate"""
        cert_file = (
            '/usr/local/share/ca-certificates/keystone_juju_ca_cert.crt')
        if ca_cert:
            with self.update_central_cacerts([cert_file], update_certs):
                with open(cert_file, 'w') as crt:
                    crt.write(ca_cert)

    def run_update_certs(self):
        """Update certifiacte

        Run update-ca-certificates to update the directory /etc/ssl/certs to
        hold SSL certificates and generates ca-certificates.crt, a concatenated
        single-file list of certificates
        """
        subprocess.check_call(['update-ca-certificates', '--fresh'])

    def update_peers(self, cluster):
        for addr_type in os_ip.ADDRESS_MAP.keys():
            cidr = self.config.get(os_ip.ADDRESS_MAP[addr_type]['config'])
            laddr = ch_ip.get_address_in_network(cidr)
            if laddr:
                cluster.set_address(
                    os_ip.ADDRESS_MAP[addr_type]['binding'],
                    laddr)


# TODO: drop once charmhelpers releases a new version
#       with this function in the fetch helper (> 0.9.1)
def get_upstream_version(package):
    """Determine upstream version based on installed package

    @returns None (if not installed) or the upstream version
    """
    import apt_pkg
    cache = fetch.apt_cache()
    try:
        pkg = cache[package]
    except:
        # the package is unknown to the current apt cache.
        return None

    if not pkg.current_ver:
        # package is known, but no version is currently installed.
        return None

    return apt_pkg.upstream_version(pkg.current_ver.ver_str)
