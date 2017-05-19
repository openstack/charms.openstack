import charmhelpers.contrib.openstack.utils as os_utils
import charmhelpers.core.hookenv as hookenv
import charmhelpers.core.unitdata as unitdata
import charms.reactive as reactive

from charms_openstack.charm.classes import OpenStackCharm
from charms_openstack.charm.core import register_os_release_selector

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
    'upgrade-charm',
]

# Where to store the default handler functions for each default state
_default_handler_map = {}

# Used to store the discovered release version for caching between invocations
OPENSTACK_RELEASE_KEY = 'charmers.openstack-release-version'


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
        instance = OpenStackCharm.singleton
        instance.config_changed()
        instance.assess_status()


@_map_default_handler('upgrade-charm')
def make_default_upgrade_charm_handler():

    @reactive.hook('upgrade-charm')
    def default_upgrade_charm():
        """Default handler for the 'upgrade-charm' hook.
        This calls the charm.singleton.upgrade_charm() function as a default.
        """
        OpenStackCharm.singleton.upgrade_charm()


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
        instance = OpenStackCharm.singleton
        hookenv.application_version_set(instance.application_version)
        instance.assess_status()
