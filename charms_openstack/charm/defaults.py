import charmhelpers.contrib.openstack.utils as os_utils
import charmhelpers.core.hookenv as hookenv
import charmhelpers.core.unitdata as unitdata
import charms.reactive as reactive

from charms_openstack.charm.classes import OpenStackCharm
from charms_openstack.charm.core import get_charm_instance
from charms_openstack.charm.core import register_os_release_selector
from charms_openstack.charm.core import register_package_type_selector
from charms_openstack.charm.core import OPENSTACK_RELEASE_KEY
from charms_openstack.charm.core import OPENSTACK_PACKAGE_TYPE_KEY

# The default handlers that charms.openstack provides.
ALLOWED_DEFAULT_HANDLERS = [
    'charm.installed',
    'amqp.connected',
    'shared-db.connected',
    'identity-service.connected',
    'identity-service.available',
    'config.changed',
    'config.rendered',
    'charm.default-select-release',
    'charm.default-select-package-type',
    'update-status',
    'upgrade-charm',
    'certificates.available',
    'storage-backend.connected',
    'cluster.available',
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
    """Set the default charm.installed state so that the default handler in
    layer-openstack can run.
    Convoluted, because charms.reactive will only run handlers in the reactive
    or hooks directory.
    """
    reactive.set_state('charms.openstack.do-default-charm.installed')


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
        release_version = None
        # Using the cached OpenStack version will cause undesired behaviors
        # if the charm is a subordinate. The charm local cache is firstly
        # populated during the charm install and after that, only during the
        # openstack upgrades. If the charm is a subordinate, the version will
        # always remain the same.
        if not hookenv.is_subordinate():
            release_version = unitdata.kv().get(OPENSTACK_RELEASE_KEY, None)

        if release_version is None:
            try:
                # First make an attempt of determining release from a charm
                # instance defined package codename dictionary.
                singleton = get_charm_instance()
                if singleton.release_pkg is None:
                    raise RuntimeError("release_pkg is not set")
                release_version = singleton.get_os_codename_package(
                    singleton.release_pkg, singleton.package_codenames,
                    apt_cache_sufficient=(not singleton.source_config_key))
                if release_version is None:
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
                release_version = os_utils.os_release(
                    pkg, source_key=singleton.source_config_key)

            # Skip caching the release if the charm is a subordinate.
            if not hookenv.is_subordinate():
                unitdata.kv().set(OPENSTACK_RELEASE_KEY, release_version)

        return release_version


@_map_default_handler('charm.default-select-package-type')
def make_default_select_package_type_handler():
    """This handler is a bit more unusual, as it just sets the package type
    selector using the @register_package_type_selector decorator
    """

    @register_package_type_selector
    def default_select_package_type():
        """Determine the package type (snap or deb) based on the
        configuration option indicated in the source_config_key
        class variable.  (deafult: 'openstack-origin')

        Note that this function caches the package type after the first
        install so that it doesn't need to keep going and getting it from
        the config information.
        """
        package_type = unitdata.kv().get(OPENSTACK_PACKAGE_TYPE_KEY, None)
        if package_type is None:
            if os_utils.snap_install_requested():
                package_type = 'snap'
            else:
                package_type = 'deb'
            unitdata.kv().set(OPENSTACK_PACKAGE_TYPE_KEY, package_type)
        return package_type


@_map_default_handler('amqp.connected')
def make_default_amqp_connection_handler():
    """Set the default amqp.connected state so that the default handler in
    layer-openstack can run.
    Convoluted, because charms.reactive will only run handlers in the reactive
    or hooks directory.
    """
    reactive.set_state('charms.openstack.do-default-amqp.connected')


@_map_default_handler('certificates.available')
def make_default_certificates_available_handler():
    """Set the default certificates.available state so that the default handler
    in layer-openstack can run.
    Convoluted, because charms.reactive will only run handlers in the reactive
    or hooks directory.
    """
    reactive.set_state('charms.openstack.do-default-certificates.available')


@_map_default_handler('storage-backend.connected')
def make_default_storage_backend_connected_handler():
    """Set the default storage-backend.connected state so that the default
    handler in layer-openstack can run.
    Convoluted, because charms.reactive will only run handlers in the reactive
    or hooks directory.
    """
    reactive.set_state('charms.openstack.do-default-storage-backend.connected')


@_map_default_handler('shared-db.connected')
def make_default_setup_database_handler():
    """Set the default shared-db.connected state so that the default handler in
    layer-openstack can run.
    Convoluted, because charms.reactive will only run handlers in the reactive
    or hooks directory.
    """
    reactive.set_state('charms.openstack.do-default-shared-db.connected')


@_map_default_handler('identity-service.connected')
def make_default_setup_endpoint_connection():
    """Set the default identity-service.connected state so that the default
    handler in layer-openstack can run.
    Convoluted, because charms.reactive will only run handlers in the reactive
    or hooks directory.
    """
    reactive.set_state(
        'charms.openstack.do-default-identity-service.connected')


@_map_default_handler('identity-service.available')
def make_setup_endpoint_available_handler():
    """Set the default identity-service.available state so that the default
    handler in layer-openstack can run.
    Convoluted, because charms.reactive will only run handlers in the reactive
    or hooks directory.
    """
    reactive.set_state(
        'charms.openstack.do-default-identity-service.available')


@_map_default_handler('config.changed')
def make_default_config_changed_handler():
    """Set the default config.changed state so that the default handler in
    layer-openstack can run.
    Convoluted, because charms.reactive will only run handlers in the reactive
    or hooks directory.
    """
    reactive.set_state('charms.openstack.do-default-config.changed')


@_map_default_handler('upgrade-charm')
def make_default_upgrade_charm_handler():
    """Set the default upgrade-charm state so that the default handler in
    layer-openstack can run.
    Convoluted, because charms.reactive will only run handlers in the reactive
    or hooks directory.
    """
    reactive.set_state('charms.openstack.do-default-upgrade-charm')


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
    """Set the default upgrade-status state so that the default handler in
    layer-openstack can run.
    Convoluted, because charms.reactive will only run handlers in the reactive
    or hooks directory.
    """
    reactive.set_state('charms.openstack.do-default-update-status')


@_map_default_handler('config.rendered')
def make_default_config_rendered_handler():
    """Set the default config.rendered state so that the reactive handler runs.
    """
    reactive.set_state('charms.openstack.do-default-config-rendered')


@_map_default_handler('cluster.available')
def make_default_cluster_available_handler():
    """Set the default cluster.available state so that the default handler in
    layer-openstack-api can run.
    """
    reactive.set_state('charms.openstack.do-default-cluster.available')
