import collections
import functools
import itertools
import os
import re
import subprocess

import charmhelpers.contrib.hahelpers.cluster as ch_cluster
import charmhelpers.contrib.openstack.policyd as os_policyd
import charmhelpers.contrib.openstack.templating as os_templating
import charmhelpers.contrib.openstack.utils as os_utils
import charmhelpers.core.hookenv as hookenv
import charmhelpers.core.host as ch_host
import charmhelpers.core.templating
import charmhelpers.core.unitdata as unitdata
import charmhelpers.fetch as fetch
import charms.reactive as reactive
import charms.reactive.flags as flags
import charms.reactive.relations as relations

import charms_openstack.adapters as os_adapters
import charms_openstack.ip as os_ip


# Used to store the discovered release version for caching between invocations
OPENSTACK_RELEASE_KEY = 'charmers.openstack-release-version'
OPENSTACK_PACKAGE_TYPE_KEY = 'charmers.openstack-package-type'


# _releases{} is a dictionary of release -> class that is instantiated
# according to the release that is being requested.  i.e. a charm can
# handle more than one release. The BaseOpenStackCharm() derived class sets the
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

# `_get_charm_instance_function` holds a function that takes optionally takes a
# release and returns the corresponding charm class.
_get_charm_instance_function = None

# `_package_type_selector_function` holds a function that optionally takes a
# package type and commutes it to another package type or just returns a
# package type. This is to enable the defining code to define which
# package type is used.
_package_type_selector_function = None


def optional_interfaces(args, *interfaces):
    """Return a tuple with possible optional interfaces

    :param args: a list of reactive interfaces
    :param *interfaces: list of strings representing possible reactive
        interfaces.
    :returns: [list of reactive interfaces]
    """
    return args + tuple(ri for ri in (relations.endpoint_from_flag(i)
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
        return self.f(BaseOpenStackCharm.singleton, *args, **kwargs)

    def __enter__(self):
        """with statement as gets the charm instance"""
        return BaseOpenStackCharm.singleton

    def __exit__(self, *_):
        # Never bother with the exception
        return False


def default_get_charm_instance(release=None, package_type='deb', *args,
                               **kwargs):
    """Get an instance of the charm based on the release (or use the
    default if release is None).

    OS releases are in alphabetical order, so it looks for the first release
    that is provided if release is None, otherwise it finds the release that is
    before or equal to the release passed.

    Note that it passes args and kwargs to the class __init__() method.

    :param release: lc string representing release wanted.
    :param package_type: string representing the package type required
    :returns: BaseOpenStackCharm() derived class according to cls.releases
    """
    if len(_releases.keys()) == 0:
        raise RuntimeError(
            "No derived BaseOpenStackCharm() classes registered")
    # Note that this relies on OS releases being in alphabetical order
    known_releases = sorted(_releases.keys())
    cls = None
    if release is None:
        # take the latest version of the charm if no release is passed.
        cls = _releases[known_releases[-1]][package_type]
    else:
        # check that the release is a valid release
        if release not in os_utils.OPENSTACK_RELEASES:
            raise RuntimeError(
                "Release {} is not a known OpenStack release?".format(release))
        release_index = os_utils.OPENSTACK_RELEASES.index(release)
        if (release_index <
                os_utils.OPENSTACK_RELEASES.index(known_releases[0])):
            raise RuntimeError(
                "Release {} is not supported by this charm. Earliest support "
                "is {} release".format(release, known_releases[0]))
        else:
            # try to find the release that is supported.
            for known_release in reversed(known_releases):
                if (release_index >=
                        os_utils.OPENSTACK_RELEASES.index(known_release) and
                        package_type in _releases[known_release]):
                    cls = _releases[known_release][package_type]
                    break
    if cls is None:
        raise RuntimeError("Release {} is not supported".format(release))
    return cls(release=release, *args, **kwargs)


def get_charm_instance(release=None, package_type='deb', *args, **kwargs):
    """Get an instance of the charm based on the release (or use the
    default if release is None).

    Use a bespoke method if one is registered otherwise uses the default
    default_get_charm_instance.

    :param release: lc string representing release wanted.
    :param package_type: string representing the package type required
    :returns: BaseOpenStackCharm() derived class according to cls.releases
    """
    return (_get_charm_instance_function or default_get_charm_instance)(
        release=release,
        package_type=package_type,
        *args,
        **kwargs)


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


def register_get_charm_instance(f):
    """Register a function that supplies a charm class for a given
    release.

    Usage:

        @register_get_charm_instance
        def my_get_charm_instance(release=None, *args, **kwargs):
            if release == X:
                cls = CharmClassX
            return cls(release=release, *args, **kwargs)

    The function should return a string which is an OS release.
    """
    global _get_charm_instance_function
    if _get_charm_instance_function is None:
        # we can only do this once in a system invocation.
        _get_charm_instance_function = f
    else:
        raise RuntimeError(
            "Only a single get_charm_instance is supported."
            " Called with {}".format(f.__name__))
    return f


def register_package_type_selector(f):
    """Register a function that determines what the package type is for the
    invocation run.  This allows the charm to define HOW the package type is
    determined.

    Usage:

        @register_package_type_selector
        def my_package_type_selector():
            return package_type_chooser()

    The function should return a string which is 'snap' or 'deb'.
    """
    global _package_type_selector_function
    if _package_type_selector_function is None:
        # we can only do this once in a system invocation.
        _package_type_selector_function = f
    else:
        raise RuntimeError(
            "Only a single package_type_selector_function is supported."
            " Called with {}".format(f.__name__))
    return f


# TODO(jamespage): move to snap charmhelper
def get_snap_version(snap, fatal=True):
    """Determine version for an installed snap.

    :param package: str Snap name to lookup (ie. in snap list)
    :param fatal: bool Raise exception if snap not installed
    :returns: str version of snap installed
    """
    cmd = ['snap', 'list', snap]
    try:
        out = subprocess.check_output(cmd).decode('UTF-8')
    except subprocess.CalledProcessError:
        if not fatal:
            return None
        # the snap is unknown to snapd
        e = ('Could not determine version of snap: {} as it\'s'
             ' not installed'.format(snap))
        raise Exception(e)

    lines = out.splitlines()
    for line in lines:
        if snap in line:
            # Second item in list is version or a codename
            return line.split()[1]
    return None


class BaseOpenStackCharmMeta(type):
    """Metaclass to provide a classproperty of 'singleton' so that class
    methods in the derived BaseOpenStackCharm() class can simply use
    cls.singleton to get the instance of the charm.

    Thus cls.singleton is a singleton for accessing and creating the default
    BaseOpenStackCharm() derived class.  This is to avoid a lot of boilerplate
    in the classmethods for the charm code.  This is because, usually, a
    classmethod is only called once per invocation of the script.

    Thus in the derived charm code we can do this:

        cls.singleton.instance_method(...)

    and this will instatiate the charm and call instance_method() on it.

    Note that self.singleton is also defined as a property for completeness so
    that cls.singleton and self.singleton give consistent results.
    """

    def __init__(cls, name, mro, members):
        """Receive the BaseOpenStackCharm() (derived) class and store the
        release that it works against.  Each class defines a 'release' that it
        handles and the order of releases (as given in charmhelpers) determines
        (for any release) which BaseOpenStackCharm() derived class is the
        handler for that class.

        :param name: string for class name.
        :param mro: tuple of base classes.
        :param members: dictionary of name to class attribute (f, p, a, etc.)
        """
        global _releases
        # Do not attempt to calculate the release for an abstract class
        if members.get('abstract_class', False):
            return
        if 'release' in members.keys():
            package_type = members.get('package_type', 'deb')
            if package_type not in ('deb', 'snap'):
                raise RuntimeError(
                    "Package type {} is not a known type"
                    .format(package_type))
            release = members['release']
            if release not in os_utils.OPENSTACK_RELEASES:
                raise RuntimeError(
                    "Release {} is not a known OpenStack release"
                    .format(release))
            if (release in _releases.keys() and
                    package_type in _releases[release].keys()):
                raise RuntimeError(
                    "Release {} defined more than once in classes {} and {} "
                    " (at least)"
                    .format(release,
                            _releases[release][package_type].__name__,
                            name))
            # store the class against the release.
            if release not in _releases:
                _releases[release] = {}
            _releases[release][package_type] = cls
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
            package_type = None
            # see if a _release_selector_function has been registered.
            if _release_selector_function is not None:
                release = _release_selector_function()
            if _package_type_selector_function is not None:
                package_type = _package_type_selector_function()
            _singleton = get_charm_instance(release=release,
                                            package_type=package_type or 'deb')
        return _singleton


class BaseOpenStackCharm(object, metaclass=BaseOpenStackCharmMeta):
    """
    Base class for all OpenStack Charm classes;

    It implements the basic plumbing to support a singleton object representing
    the current series of OpenStack in use.
    """

    abstract_class = True

    # The adapters class that this charm uses to adapt interfaces.
    # If None, then it defaults to OpenstackRelationsAdapter
    adapters_class = os_adapters.OpenStackRelationAdapters

    # The configuration base class to use for the charm
    # If None, then the default ConfigurationAdapter is used.
    configuration_class = os_adapters.ConfigurationAdapter

    # Dictionary mapping services to ports for public, admin and
    # internal endpoints
    api_ports = {}

    package_codenames = {}

    # File permissions
    # config files written with 'group' read permission but always
    # owned by root.
    user = 'root'
    group = 'root'

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
        :param release: the release for this instance or None
        """
        self.config = config or hookenv.config()
        self.release = release
        self.__adapters_instance = None
        self.__interfaces = interfaces or []
        self.__options = None
        super().__init__()

    @property
    def adapters_instance(self):
        """Lazily return the adapters_interface which is constructable from the
        self.__interfaces and if the self.adapters_class exists

        Note by DEFAULT self.adapters_class is set; this would only be None
        if a derived class wanted to switch off this functionality!

        :returns: the adapters_instance or None if there is not
            self.adapters_class
        """
        if self.__adapters_instance is None and self.adapters_class:
            self.__adapters_instance = self.adapters_class(
                self.__interfaces, charm_instance=self)
        return self.__adapters_instance

    def get_adapter(self, state, adapters_instance=None):
        """Get the adapted interface for a state or None if the state doesn't
        yet exist.

        Uses the self.adapters_instance to get the adapter if the passed
        adapters_instance is None, which should be fine for almost every
        possible usage.

        :param state: <string> of the state to get an adapter for.
        :param adapters_instance: Class which has make_adapter() method
        :returns: None if the state doesn't exist, or the adapter
        """
        interface = relations.endpoint_from_flag(state)
        if interface is None:
            return None
        adapters_instance = adapters_instance or self.adapters_instance
        if adapters_instance is None:
            adapters_instance = self.adapters_class([], charm_instance=self)
        _, adapter = adapters_instance.make_adapter(interface)
        return adapter

    @property
    def options(self):
        """Lazily return the options for the charm when this is first called

        We want the fancy options here too that's normally on the adapters
        class as it means the charm get access to computed options as well.

        :returns: an options instance based on the configuration_class
        """
        if self.__options is None:
            self.__options = os_adapters.make_default_options(
                base_cls=getattr(self, 'configuration_class', None),
                charm_instance=self)
        return self.__options

    @property
    def active_api_ports(self):
        """Return the api port map adjusting ports as required.
        """
        # If charm class sets ssl_port_bump to True then
        # prepend a 1 to the port number eg 8779 -> 18779
        ssl_port_bump = getattr(self, 'ssl_port_bump', False)
        if ssl_port_bump and self.get_state('ssl.enabled'):
            _api_ports = {}
            for svc in self.api_ports:
                _api_ports[svc] = {}
                for ep_type, port in self.api_ports[svc].items():
                    _api_ports[svc][ep_type] = int("1{}".format(port))
            return _api_ports
        else:
            return self.api_ports

    def api_port(self, service, endpoint_type=os_ip.PUBLIC):
        """Return the API port for a particular endpoint type from the
        self.active_api_ports{}.

        :param service: string for service name
        :param endpoing_type: one of charm.openstack.ip.PUBLIC| INTERNAL| ADMIN
        :returns: port (int)
        """
        return self.active_api_ports[service][endpoint_type]

    def set_state(self, state, value=None):
        """proxy for charms.reactive.bus.set_state()"""
        reactive.bus.set_state(state, value)

    def remove_state(self, state):
        """proxy for charms.reactive.bus.remove_state()"""
        reactive.bus.remove_state(state)

    def get_state(self, state):
        """proxy for charms.reactive.bus.get_state()"""
        return reactive.bus.get_state(state)

    @staticmethod
    def get_os_codename_snap(snap, codenames, fatal=True):
        """Derive OpenStack release codename from an installed snap.

        :param package: str Snap name to lookup (ie. in snap list)
        :param codenames: dict of OrderedDict
            {
             'snap1': collections.OrderedDict([
                 ('2', 'mitaka'),
                 ('3', 'newton'),
                 ('4', 'ocata'), ]),
             'snap2': collections.OrderedDict([
                 ('12', 'mitaka'),
                 ('13', 'newton'),
                 ('14', 'ocata'), ]),
            }
        :param fatal: bool Raise exception if snap not installed
        :returns: str OpenStack version name corresponding to package
        """
        version_or_codename = get_snap_version(snap, fatal)

        match = re.match(r'^(\d+)\.(\d+)', version_or_codename)
        if match:
            version = match.group(0)
            # Generate a major version number for newer semantic
            # versions of openstack projects
            major_vers = version.split('.')[0]
            try:
                return codenames[snap][major_vers]
            except KeyError:
                # NOTE(jamespage): fallthrough to codename assumption
                pass

        # NOTE(jamespage): fallback to codename assumption
        return version_or_codename

    @staticmethod
    def get_package_version(package, apt_cache_sufficient=False):
        """Derive OpenStack release codename from a package.

        :param package: Package name to lookup (ie. in apt cache)
        :type package: str
        :param apt_cache_sufficient: When False (the default) version from an
            installed package will be used, when True version from the systems
            APT cache will be used.  This is useful for subordinate charms who
            need working release selection prior to package installation and
            has no way of using fall back to version of a package the principle
            charm has installed nor package source configuration option.
        :type apt_cache_sufficient: bool
        :returns: OpenStack version name corresponding to package
        :rtype: Optional[str]
        :raises: AttributeError, ValueError
        """
        cache = fetch.apt_cache()

        try:
            pkg = cache[package]
        except KeyError:
            # the package is unknown to the current apt cache.
            e = ValueError(
                'Could not determine version of package with no installation '
                'candidate: {}'.format(package))
            raise e

        if apt_cache_sufficient:
            vers = fetch.apt_pkg.upstream_version(pkg.version)
        else:
            vers = fetch.apt_pkg.upstream_version(pkg.current_ver.ver_str)

        # x.y match only for 20XX.X
        # and ignore patch level for other packages
        match = re.match(r'^(\d+)\.(\d+)', vers)

        if match:
            vers = match.group(0)

        return vers

    @staticmethod
    def get_os_codename_package(package, codenames, fatal=True,
                                apt_cache_sufficient=False):
        """Derive OpenStack release codename from a package.

        :param package: Package name to lookup (ie. in apt cache)
        :type package: str
        :param codenames: Map of package to (version, os_release) tuples.
            Example:
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
        :type codenames: Dict[str,collections.OrderedDict[Tuple(str,str)]]
        :param fatal: Raise exception if pkg not installed
        :type fatal: bool
        :param apt_cache_sufficient: When False (the default) version from an
            installed package will be used, when True version from the systems
            APT cache will be used.  This is useful for subordinate charms who
            need working release selection prior to package installation and
            has no way of using fall back to version of a package the principle
            charm has installed nor package source configuration option.
        :type apt_cache_sufficient: bool
        :returns: OpenStack version name corresponding to package
        :rtype: Optional[str]
        :raises: AttributeError, ValueError
        """
        try:
            vers = BaseOpenStackCharm.get_package_version(
                package,
                apt_cache_sufficient=apt_cache_sufficient)
            # Generate a major version number for newer semantic
            # versions of openstack projects
            major_vers = vers.split('.')[0]
        except Exception:
            if fatal:
                raise
            else:
                return None
        if (package in codenames and
                major_vers in codenames[package]):
            return codenames[package][major_vers]

    def get_os_version_snap(self, snap, fatal=True):
        """Derive OpenStack version number from an installed snap.

        :param package: str Snap name to lookup in snap list
        :param fatal: bool Raise exception if snap not installed
        :returns: str OpenStack version number corresponding to snap
        """
        if os_utils.snap_install_requested():
            codename = self.get_os_codename_snap(snap,
                                                 self.snap_codenames,
                                                 fatal=fatal)
            if not codename:
                return None

            for version, cname in os_utils.OPENSTACK_CODENAMES.items():
                if cname == codename:
                    return version

        return None

    def get_os_version_package(self, package, fatal=True):
        """Derive OpenStack version number from an installed package.

        :param package: str Package name to lookup in apt cache
        :param fatal: bool Raise exception if pkg not installed
        :returns: str OpenStack version number corresponding to package
        """
        if not os_utils.snap_install_requested():
            codename = self.get_os_codename_package(
                package, self.package_codenames or os_utils.PACKAGE_CODENAMES,
                fatal=fatal)
            if not codename:
                return None

            for version, cname in os_utils.OPENSTACK_CODENAMES.items():
                if cname == codename:
                    return version

        return None


class BaseOpenStackCharmActions(object):
    """Default actions that an OpenStack charm can expect to have to do.

    This includes things like 'installation', 'rendering configurations', etc.

    It is designed as a mixin, and is separated out so that it is easier to
    maintain.

    i.e.

    class OpenStackCharm(BaseOpenStackCharm,
                         BaseOpenStackCharmActions):
        ... stuff ...
    """

    @property
    def all_packages(self):
        """List of packages to be installed

        Relies on the class variable 'packages'

        @return ['pkg1', 'pkg2', ...]
        """
        return self.packages

    @property
    def all_snaps(self):
        """List of snaps to be installed

        Relies on the class variable 'snaps'

        @return ['snap1', 'snap2', ...]
        """
        return self.snaps

    @property
    def primary_snap(self):
        """Primary snap to use for configuration

        Relies on the class variable 'snaps'

        :return string: first snap found in 'snaps'
        """
        if self.snaps:
            return self.snaps[0]
        return None

    def install(self):
        """Install packages or snaps related to this charm based on
        contents of self.packages or self.snaps attribute.
        """
        packages = fetch.filter_installed_packages(
            self.all_packages)
        if packages:
            hookenv.status_set('maintenance', 'Installing packages')
            fetch.apt_install(packages, fatal=True)

        if os_utils.snap_install_requested():
            if self.all_snaps:
                hookenv.status_set('maintenance', 'Installing snaps')
                os_utils.install_os_snaps(
                    os_utils.get_snaps_install_info_from_origin(
                        self.all_snaps,
                        self.config[self.source_config_key],
                        mode=self.snap_mode)
                )

        # AJK: we set this as charms can use it to detect installed state
        self.set_state('{}-installed'.format(self.name))
        self.update_api_ports()
        if packages:
            # NOTE(fnordahl): Update status only if we actually performed
            # package installation to avoid uneccessary status transitions.
            # LP: #1861775
            hookenv.status_set('maintenance',
                               'Installation complete - awaiting next status')

    def configure_source(self, config_key=None):
        """Configure installation source.

        :param config_key: Config item (default: value indicated in the
                           source_config_key class variable)
        :type config_key: Optional[str]

        This adds an installation source for deb packages and then updates the
        packages list on the unit.
        """
        config_key = config_key or self.source_config_key
        source, key = os_utils.get_source_and_pgp_key(
            self.config[config_key])
        fetch.add_source(source, key)
        fetch.apt_update(fatal=True)

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

    def service_stop(self, service_name):
        """Stop the specified service.

        Meant to be overridden by child classes in scenarios where clustering
        software like Pacemaker is used.

        :param service_name: The service to stop.
        :type service_name: str
        """
        ch_host.service_stop(service_name)

    def service_start(self, service_name):
        """Start the specified service.

        Meant to be overridden by child classes in scenarios where clustering
        software like Pacemaker is used.

        :param service_name: The service to start.
        :type service_name: str
        """
        ch_host.service_start(service_name)

    def service_restart(self, service_name):
        """Restart the specified service.

        Meant to be overridden by child classes in scenarios where clustering
        software like Pacemaker is used.

        :param service_name: The service to restart.
        :type service_name: str
        """
        ch_host.service_restart(service_name)

    def service_reload(self, service_name, restart_on_failure=False):
        """Reload the specified service.

        Meant to be overridden by child classes in scenarios where clustering
        software like Pacemaker is used.

        :param service_name: The service to reload.
        :type service_name: str
        """
        ch_host.service_reload(service_name, restart_on_failure)

    def restart_on_change(self):
        """Restart the services in the self.restart_map{} attribute if any of
        the files identified by the keys changes for the wrapped call.

        Usage:

           @restart_on_change(restart_map, ...)
           def function_that_might_trigger_a_restart(...)
               ...

        Or:

           with restart_on_change(restart_map, ...):
               do_stuff_that_might_trigger_a_restart()
               ...
        """
        return ch_host.restart_on_change(
            self.full_restart_map,
            stopstart=True,
            restart_functions=getattr(self, 'restart_functions', None))

    def restart_all(self):
        """Restart all the services configured in the self.services[]
        attribute.
        """
        for svc in self.services:
            self.service_restart(svc)

    def render_all_configs(self, adapters_instance=None):
        """Render (write) all of the config files identified as the keys in the
        self.restart_map{}

        Note: If the config file changes on storage as a result of the config
        file being written, then the services are restarted as per
        the restart_the_services() method.

        If adapters_instance is None then the self.adapters_instance is used
        that was setup in the __init__() method.  Note, if no interfaces were
        passed (the default) then there will be no interfaces for this
        function!

        :param adapters_instance: [optional] the adapters_instance to use.
        """
        self.render_configs(self.full_restart_map.keys(),
                            adapters_instance=adapters_instance)

    def _get_string_template(self, conf, adapters_instance):
        """
        Find out if a charm class provides meta information about whether
        this is a template to be fetched from a string dynamically or not.
        """
        config_template = None
        tmpl_meta = self.string_templates.get(conf)
        if tmpl_meta:
            # meta information exists but not clear if an attribute has
            # been set yet either via config option or via relation data
            config_template = False
            rel_name, _property = tmpl_meta
            try:
                config_template_adapter = getattr(adapters_instance,
                                                  rel_name)
                try:
                    config_template = getattr(config_template_adapter,
                                              _property)
                except AttributeError:
                    raise RuntimeError('{} does not contain {} property'
                                       .format(config_template_adapter,
                                               _property))
            except AttributeError:
                hookenv.log('Skipping a string template for {} as a '
                            'relation adapter is not present'
                            .format(rel_name), level=hookenv.DEBUG)
        return config_template

    def render_configs(self, configs, adapters_instance=None):
        """Render the configuration files identified in the list passed as
        configs.

        Configs may not only be loaded via OpenStack loaders but also via
        string templates passed via config options or from relation data.
        This must be explicitly declared via string_templates dict of a given
        derived charm class by using a relation name that identifies a relation
        adapter or config option adapter and a property to be used from that
        adapter instance.

        :param configs: list of strings, the names of the configuration files.
        :param adapters_instance: [optional] the adapters_instance to use.
        """
        if adapters_instance is None:
            interfaces = []
            for f in flags.get_flags():
                ep_from_f = relations.endpoint_from_flag(f)
                if ep_from_f:
                    interfaces.append(ep_from_f)
            try:
                adapters_instance = self.adapters_class(interfaces,
                                                        charm_instance=self)
            except TypeError:
                adapters_instance = self.adapters_class(interfaces)

        with self.restart_on_change():
            for conf in configs:
                # check if we need to load a template from a string
                config_template = self._get_string_template(conf,
                                                            adapters_instance)
                if config_template is False:
                    # got a string template but it was not provided which
                    # means we need to skip this config to avoid rendering
                    return

                def _render(source):
                    charmhelpers.core.templating.render(
                        source=source,
                        template_loader=os_templating.get_loader(
                            'templates/', self.release),
                        target=conf,
                        context=adapters_instance,
                        config_template=config_template,
                        group=self.group,
                        perms=self.permission_override_map.get(conf) or 0o640,
                    )
                try:
                    _render(os.path.basename(conf))
                except LookupError:
                    # if no template is found try looking for files named after
                    # the absolute path of target with path separators replaced
                    # by underscores.  This convention is useful when charm
                    # author need to provide templates with ambiguous basenames
                    _render('_'.join(conf.split(os.path.sep))[1:])

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

    def config_changed(self):
        """A Nop that can be overridden in the derived charm class.
        If the default 'config.changed' state handler is used, then this will
        be called as a result of that state.
        """
        pass

    def upgrade_charm(self):
        """Called (at least) by the default handler (if that is used).  This
        version just checks that the ports that are open should be open and
        that the ports that are closed should be closed.  If the charm upgrade
        alters the ports then update_api_ports() function will adjust the ports
        as needed.

        Obsolete packages will also be assessed for removal; if packages are
        removed, then services will be restarted to pickup any changes.
        """
        self.update_api_ports()
        self.install()
        if self.remove_obsolete_packages():
            self.restart_all()

    def update_api_ports(self, ports=None):
        """Update the ports list supplied (or the default ports defined in the
        classes' api_ports member) using the juju helper.

        It takes the opened-ports from Juju, checks them against the ports
        provided.  If a port is already open, then it doesn't try to open it,
        if it is closed, but should be open, then it opens it, and vice-versa.

        :param ports: List of api port numbers or None.
        """
        ports = list(map(int, (
            ports or self._default_port_list(self.active_api_ports or {}))))
        current_ports = list(map(int, self.opened_ports()))
        ports_to_open = set(ports).difference(current_ports)
        ports_to_close = set(current_ports).difference(ports)
        for p in ports_to_open:
            hookenv.open_port(p)
        for p in ports_to_close:
            hookenv.close_port(p)

    @staticmethod
    def opened_ports(protocol="tcp"):
        """Return a list of ports according to the protocol provided
        Open a service network port

        If protocol is intentionally set to None, then the list will be the
        list returnted by the Juju opened-ports command.

        :param (OPTIONAL) protocol: the protocol to check, TCP/UDP or None
        :returns: List of ports open, according to the protocol
        """
        _args = ['opened-ports']
        if protocol:
            protocol = protocol.lower()
        else:
            protocol = ''
        lines = [line for line in
                 subprocess.check_output(_args).decode('UTF-8').split()
                 if line]
        ports = []
        for line in lines:
            p, p_type = line.split('/')
            if protocol:
                if protocol == p_type.lower():
                    ports.append(p)
            else:
                ports.append(line)
        return ports

    def openstack_upgrade_available(self, package=None, snap=None):
        """Check if an OpenStack upgrade is available

        :param package: str Package name to use to check upgrade availability
        :returns: bool
        """
        if not package:
            package = self.release_pkg
        if not snap:
            snap = self.release_snap

        src = self.config[self.source_config_key]
        cur_vers = self.get_os_version_package(package)
        avail_vers = os_utils.get_os_version_install_source(src)
        if os_utils.snap_install_requested():
            cur_vers = self.get_os_version_snap(snap)
        else:
            cur_vers = self.get_os_version_package(package)

        if cur_vers is None or avail_vers is None:
            raise RuntimeError(
                "In charms_openstack.charm.core.openstack_upgrade_available() "
                "cur_vers={} and avail_vers={}, one of which is None. "
                "This usually implies that the openstack version is not "
                "present in the self.package_codenames or "
                "os_utils.PACKAGE_CODENAMES.  Please re-visit and fix."
                .format(cur_vers, avail_vers))

        fetch.apt_pkg.init()
        return fetch.apt_pkg.version_compare(avail_vers, cur_vers) == 1

    def run_upgrade(self, interfaces_list=None):
        """Upgrade OpenStack.

        :param interfaces_list: List of instances of interface classes
        :returns: None
        """
        hookenv.status_set('maintenance', 'Running openstack upgrade')
        new_src = self.config[self.source_config_key]
        new_os_rel = os_utils.get_os_codename_install_source(new_src)
        unitdata.kv().set(OPENSTACK_RELEASE_KEY, new_os_rel)
        target_charm = get_charm_instance(new_os_rel)
        target_charm.do_openstack_pkg_upgrade()
        target_charm.do_openstack_upgrade_config_render(interfaces_list)
        target_charm.do_openstack_upgrade_db_migration()

    def upgrade_if_available(self, interfaces_list):
        """Upgrade OpenStack if an upgrade is available and action-managed
           upgrades is not enabled.

        :param interfaces_list: List of instances of interface classes
        :returns: None
        """
        if self.openstack_upgrade_available(self.release_pkg):
            if self.config.get('action-managed-upgrade', False):
                hookenv.log('Not performing OpenStack upgrade as '
                            'action-managed-upgrade is enabled')
            else:
                self.run_upgrade(interfaces_list=interfaces_list)

    def do_openstack_pkg_upgrade(self):
        """Upgrade OpenStack packages and snaps

        :returns: None
        """
        new_src = self.config[self.source_config_key]
        new_os_rel = os_utils.get_os_codename_install_source(new_src)
        hookenv.log('Performing OpenStack upgrade to %s.' % (new_os_rel))

        # TODO(jamespage): Deal with deb->snap->deb migrations
        if os_utils.snap_install_requested() and self.all_snaps:
            os_utils.install_os_snaps(
                snaps=os_utils.get_snaps_install_info_from_origin(
                    self.all_snaps,
                    self.config[self.source_config_key],
                    mode=self.snap_mode),
                refresh=True)

        source, key = os_utils.get_source_and_pgp_key(
            self.config[self.source_config_key])
        fetch.add_source(source, key)
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
        self.remove_obsolete_packages()
        self.release = new_os_rel

    def remove_obsolete_packages(self):
        """Remove any packages that are no longer needed for operation

        :returns: boolean indication where packages where removed.
        """
        if self.purge_packages:
            # NOTE(jamespage):
            # Ensure packages that should be purged are actually installed
            installed_packages = list(
                set(self.purge_packages) -
                set(fetch.filter_installed_packages(self.purge_packages))
            )
            if installed_packages:
                fetch.apt_purge(packages=installed_packages,
                                fatal=True)
                fetch.apt_autoremove(purge=True, fatal=True)
                return True
        return False

    def do_openstack_upgrade_config_render(self, interfaces_list=None):
        """Render configs after upgrade

        :returns: None
        """
        if interfaces_list is not None:
            self.render_with_interfaces(interfaces_list)
        else:
            self.render_all_configs()

    def do_openstack_upgrade_db_migration(self):
        """Run database migration after upgrade

        :returns: None
        """
        if not self.sync_cmd:
            return
        elif hookenv.is_leader():
            subprocess.check_call(self.sync_cmd)
        else:
            hookenv.log("Deferring DB sync to leader", level=hookenv.INFO)

    # NOTE(jamespage): Not currently used - switch from c-h function for perf?
    def snap_install_requested(self):
        """Determine whether a snap based install is configured
        via the configuration option indicated in the source_config_key
        class variable.  (deafult: 'openstack-origin')

        :returns: None
        """
        return self.config[self.source_config_key].startswith('snap:')


class BaseOpenStackCharmAssessStatus(object):
    """Provides the 'Assess Status' functionality to the OpenStack charm class.

    It is designed as a mixin, and is separated out so that it is easier to
    maintain.

    i.e.

    class OpenStackCharm(BaseOpenStackCharm,
                         BaseOpenStackCharmAssessStatus):
        ... stuff ...


    Relies on the following class or object variables:

    # The list of services that this charm manages
    services = []
    """

    # a dict of meta tuples of the following format to render templates
    # from strings based on adapter properties (resolved at runtime):
    # {config_file_path: (relation_name, adapter property)}
    # relation names should be normalized (lowercase, underscores instead of
    # dashes; use "options" relation name for a config adapter
    string_templates = {}

    def __init__(self, *args, **kwargs):
        """Set up specific mixin requirements"""
        self.__run_assess_status = False
        super().__init__(*args, **kwargs)

    def _assess_status(self):
        """Assess the status of the unit and set the status and a useful
        message as appropriate.

        The 3 checks are:

         1. Check if the unit has been paused (using
            os_utils.is_unit_paused_set().
         2. Do a custom_assess_status_check() check.
         3. Check if the interfaces are all present (using the states that are
            set by each interface as it comes 'live'.
         4. Check that services that should be running are running.
         5. Do a custom_assess_status_last_check() check.

        Each sub-function determins what checks are taking place.

        If custom assess_status() functionality is required then the derived
        class should override any of the 4 check functions to alter the
        behaviour as required.

        Note that if ports are NOT to be checked, then the derived class should
        override :meth:`ports_to_check()` and return an empty list.

        SIDE EFFECT: this function calls status_set(state, message) to set the
        workload status in juju.
        """
        # set the application version when we set the status (always)
        # NOTE(ajkavanagh) this is not, strictly speaking, good code
        # organisation, as the 'application_version' property is in the
        # classes.py file.  However, as this is ALWAYS a mixin on that class,
        # we can get away with this.
        hookenv.application_version_set(self.application_version)

        # NOTE(ajkavanagh) we check for the Policyd override here, even though
        # most of the work is done in the plugin class PolicydOverridePlugin.
        # This is a consequence of how the assess status is implemented; we
        # simply have to get the prefix sorted here and there's no easy way to
        # get it in without a complete refactor.
        if self.config.get(os_policyd.POLICYD_CONFIG_NAME, False):
            os_policyd_prefix = "{} ".format(
                os_policyd.policyd_status_message_prefix())
        else:
            os_policyd_prefix = ""

        for f in [self.check_if_paused,
                  self.custom_assess_status_check,
                  self.check_interfaces,
                  self.check_mandatory_config,
                  self.check_services_running,
                  self.custom_assess_status_last_check]:
            state, message = f()
            if state is not None:
                hookenv.status_set(state, os_policyd_prefix + message)
                return
        # No state was particularly set, so assume the unit is active
        hookenv.status_set('active', os_policyd_prefix + 'Unit is ready')

    def assess_status(self):
        """This is a deferring version of _assess_status that only runs during
        exit. This method can be called multiple times, but it will ensure that
        the _assess_status() is only called once at the end of the charm after
        all handlers have completed.
        """
        if not self.__run_assess_status:
            self.__run_assess_status = True

            def atexit_assess_status():
                hookenv.log("Running _assess_status()", level=hookenv.DEBUG)
                self._assess_status()
            hookenv.atexit(atexit_assess_status)

    def custom_assess_status_check(self):
        """Override this function in a derived class if there are any other
        status checks that need to be done that aren't about relations, etc.

        Return (None, None) if the status is okay (i.e. the unit is active).
        Return ('active', message) do shortcut and force the unit to the active
        status.
        Return (other_status, message) to set the status to desired state.

        :param last_check: Whether we are last in the assess_status sequence
        :type last_check: bool
        :returns: None, None - no action in this function.
        """
        return None, None

    def custom_assess_status_last_check(self):
        """Override this function in a derived class if there are any other
        status checks that need to be done that should be done after all other
        checks done by this framework.

        This is a good place to put additional information about the running
        service, such as cluster status etc.

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
            ports=self.ports_to_check(self.active_api_ports))

    def ports_to_check(self, ports):
        """Return a flattened, sorted, unique list of ports from self.api_ports

        NOTE. To disable port checking, simply override this method in the
        derived class and return an empty [].

        :param ports: {key: {subkey: value}}
        :returns: [value1, value2, ...]
        """
        return self._default_port_list(ports)

    def _default_port_list(self, ports):
        """Return a flattened, sorted, unique list of ports from self.api_ports

        :param ports: {key: {subkey: value}}
        :return: [value1, value2, ...]
        """
        # NB api_ports = {key: {space: value}}
        # The chain .. map  flattens all the values into a single list
        return sorted(set(itertools.chain(*map(lambda x: x.values(),
                                               ports.values()))))

    def check_interfaces(self):
        """Check that the required interfaces have both connected and available
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
        for relation, states in states_to_check.items():
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

    def check_mandatory_config(self):
        """Check that all mandatory config has been set.

        Returns (None, None) if the interfaces are okay, or a status, message
        if any of the config is missing.

        :returns status & message info
        :rtype: (status, message) or (None, None)
        """
        missing_config = []
        status = None
        message = None
        if getattr(self, 'mandatory_config', None):
            for c in self.mandatory_config:
                if hookenv.config(c) is None:
                    missing_config.append(c)
        if missing_config:
            status = 'blocked'
            message = 'The following mandatory config is unset: {}'.format(
                ','.join(missing_config))
        return status, message

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

        This uses the self.services and self.active_api_ports to determine what
        should be checked.

        :returns: (status, message) or (None, None).
        """
        # This returns either a None, None or a status, message if the service
        # is not running or the ports are not open.
        _services, _ports = ch_cluster.get_managed_services_and_ports(
            self.services,
            self.ports_to_check(self.active_api_ports))
        return os_utils._ows_check_services_running(
            services=_services,
            ports=_ports)
