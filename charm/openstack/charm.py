# OpenStackCharm() - base class for build OpenStack charms from for the
# reactive framework.

# need/want absolute imports for the package imports to work properly
from __future__ import absolute_import

import os
import subprocess
import contextlib
import collections

import charmhelpers.contrib.openstack.templating as os_templating
import charmhelpers.contrib.openstack.utils as os_utils
import charmhelpers.core.hookenv as hookenv
import charmhelpers.core.host as ch_host
import charmhelpers.core.templating
import charmhelpers.fetch
import charms.reactive.bus

import charm.openstack.ip as os_ip


class OpenStackCharmMeta(type):
    """Metaclass to provide a classproperty of 'charm' so that class methods in
    the derived OpenStackCharm() class can simply use cls.charm to get the
    instance of the charm.

    Thus cls.charm is a singleton for accessing and creating the default
    OpenStackCharm() derived class.  This is to avoid a lot of boilerplate in
    the classmethods for the charm code.  This is because, usually, a
    classmethod is only called once per invocation of the script.

    Thus in the derived charm code we can do this:

    @classmethod
    def some_method(cls, ...):
        cls.charm.instance_method(...)

    and this will instatiate the charm and call instance_method() on it.

    Note that self.charm is also defined as a property for completeness so that
    cls.charm and self.charm give consistent results.

    """

    @property
    def charm(cls):
        if cls._charm is None:
            cls._charm = cls.get_charm_instance()
        return cls._charm


class OpenStackCharm():
    """
    Base class for all OpenStack Charm classes;
    encapulates general OpenStack charm payload operations

    Theory:
    Derive frm this class, set the name, first_release and releases class
    variables so that get_charm_instance() will create an instance of this
    charm.

    See the other class variables for details on what they are for and do.
    """

    # The singleton for the charm for this class
    _charm = None

    # releases - dictionary mapping OpenStack releases to their associated
    # specialised charm class that models this charm.
    releases = {}

    # first_release = this is the first release in which this charm works
    first_release = 'icehouse'

    # The name of the charm (for printing, etc.)
    name = 'charmname'

    # List of packages to install
    packages = []

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

    # The command used to sync "something" TODO
    sync_cmd = []

    # The list of services that this charm manages
    services = []

    # The adapters class that this charm uses to adapt interfaces.
    adapters_class = None

    @property
    def charm(self):
        """Return the only instance of the charm class in this run"""
        # Note refers back to the Metaclass property for this charm.
        return self.__class__.charm

    @classmethod
    def get_charm_instance(cls,
                           release=None,
                           *args,
                           **kwargs):
        """Get an instance of the charm based on the release (or use the
        default if release is None).

        Note that it passes args and kwargs to the class __init__() method.

        :param release: lc string representing release wanted.
        :returns: OpenStackCharm() derived class according to cls.releases
        """
        if release and release in cls.releases:
            return cls.releases[release](release=release)
        elif cls.first_release in cls.releases:
            return cls.releases[cls.first_release](release=cls.first_release)
        raise RuntimeError("Release '{}' is not supported for this charm"
                           .format(release or cls.first_release))

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
        self.adapter_instance = None
        if interfaces and self.adapters_class:
            self.adapter_instance = self.adapters_class(interfaces)

    def install(self):
        """Install packages related to this charm based on
        contents of self.packages attribute.
        """
        packages = charmhelpers.fetch.filter_installed_packages(self.packages)
        if packages:
            hookenv.status_set('maintenance', 'Installing packages')
            charmhelpers.fetch.apt_install(packages, fatal=True)
        self.set_state('{}-installed'.format(self.name))

    def set_state(self, state, value=None):
        """proxy for charms.reactive.bus.set_state()"""
        charms.reactive.bus.set_state(state, value)

    def remove_state(self, state):
        """proxy for charms.reactive.bus.remove_state()"""
        charms.reactive.bus.remove_state(state)

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
        charmhelpers.fetch.apt_update(fatal=True)

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
                     for path in self.restart_map.keys()}
        yield
        restarts = []
        for path in self.restart_map:
            if ch_host.path_hash(path) != checksums[path]:
                restarts += self.restart_map[path]
        services_list = list(collections.OrderedDict.fromkeys(restarts).keys())
        for service_name in services_list:
            ch_host.service_restart(service_name)

    def render_all_configs(self):
        """Render (write) all of the config files identified as the keys in the
        self.restart_map{}

        Note: If the config file changes on storage as a result of the config
        file being written, then the services are restarted as per
        the restart_the_services() method.
        """
        self.render_configs(self.restart_map.keys())

    def render_configs(self, configs):
        """Render the configuration files identified in the list passed as
        configs.

        :param configs: list of strings, the names of the configuration files.
        """
        with self.restart_on_change():
            for conf in configs:
                charmhelpers.core.templating.render(
                    source=os.path.basename(conf),
                    template_loader=os_templating.get_loader(
                        'templates/', self.release),
                    target=conf,
                    context=self.adapter_instance)

    def restart_all(self):
        """Restart all the services configured in the self.services[]
        attribute.
        """
        for svc in self.services:
            ch_host.service_restart(svc)

    def db_sync(self):
        """Perform a database sync using the command defined in the
        self.sync_cmd attribute. The services defined in self.services are
        restarted after the database sync.
        """
        sync_done = hookenv.leader_get(attribute='db-sync-done')
        if not sync_done:
            subprocess.check_call(self.sync_cmd)
            hookenv.leader_set({'db-sync-done': True})
            # Restart services immediatly after db sync as
            # render_domain_config needs a working system
            self.restart_all()
