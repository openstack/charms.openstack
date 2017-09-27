import base64
import contextlib
import os
import random
import string
import subprocess

import charmhelpers.contrib.network.ip as ch_ip
import charmhelpers.contrib.openstack.utils as os_utils
import charmhelpers.core.hookenv as hookenv
import charmhelpers.core.host as ch_host
import charmhelpers.fetch as fetch
import charms.reactive as reactive

from charms_openstack.charm.core import (
    BaseOpenStackCharm,
    BaseOpenStackCharmActions,
    BaseOpenStackCharmAssessStatus,
    get_snap_version,
)
from charms_openstack.charm.utils import (
    get_upstream_version,
    is_data_changed,
)
import charms_openstack.adapters as os_adapters
import charms_openstack.ip as os_ip

VIP_KEY = "vip"
CIDR_KEY = "vip_cidr"
IFACE_KEY = "vip_iface"
APACHE_SSL_VHOST = '/etc/apache2/sites-available/openstack_https_frontend.conf'


class OpenStackCharm(BaseOpenStackCharm,
                     BaseOpenStackCharmActions,
                     BaseOpenStackCharmAssessStatus):
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

    # package type - package type (deb or snap) in which this charm works
    package_type = 'deb'

    # The name of the charm (for printing, etc.)
    name = 'charmname'

    # List of packages to install
    packages = []

    # List of snaps to install
    snaps = []

    # Mode to install snaps in (jailmode/devmode/classic)
    snap_mode = 'jailmode'

    # Package to determine application version from
    # defaults to first in packages if not provided
    version_package = release_pkg = None

    # Snap to determine application version from;
    # defaults to first in snaps if not provided
    version_snap = release_snap = None

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

    # package_codenames = {}

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
        the charm, as indicated by the version_package or version_snap
        attribute
        """
        if os_utils.snap_install_requested():
            if not self.version_snap:
                self.version_snap = self.snaps[0]
            version = get_snap_version(self.version_snap,
                                       fatal=False)
            if not version:
                version = os_utils.get_os_codename_install_source(
                    self.config['openstack-origin']
                )
        else:
            if not self.version_package:
                self.version_package = self.packages[0]
            version = get_upstream_version(
                self.version_package
            )
            if not version:
                version = os_utils.os_release(self.version_package)
        return version


class OpenStackAPICharm(OpenStackCharm):
    """The base class for API OS charms -- this just bakes in the default
    configuration and adapter classes.
    """
    abstract_class = True

    MEMCACHE_CONF = '/etc/memcached.conf'

    # The adapters class that this charm uses to adapt interfaces.
    # If None, then it defaults to OpenstackRelationAdapters
    adapters_class = os_adapters.OpenStackAPIRelationAdapters

    # The configuration base class to use for the charm
    # If None, then the default ConfigurationAdapter is used.
    configuration_class = os_adapters.APIConfigurationAdapter

    # These can be overriden in the derived charm class to allow specialism of
    # config files.  These values are read in the APIConfigurationAdapter and
    # used to furnish the dictionary provided from the property
    # 'wsgi_worker_context'.  e.g. config.wsgi_worker_context.processes would
    # be the number of processes for the main API wsgi worker.
    wsgi_script = None
    wsgi_admin_script = None
    wsgi_public_script = None
    wsgi_process_weight = None  # use the default from charm-helpers
    wsgi_admin_process_weight = None  # use the default from charm-helpers
    wsgi_public_process_weight = None  # use the default from charm-helpers

    def upgrade_charm(self):
        """Setup token cache in case previous charm version did not."""
        self.setup_token_cache()
        super().upgrade_charm()

    def install(self):
        """Install packages related to this charm based on
        contents of self.packages attribute.
        """
        self.configure_source()
        super().install()

    def setup_token_cache(self):
        """Check if a token cache package is needed and install it if it is"""
        if fetch.filter_installed_packages(self.token_cache_pkgs()):
            self.install()

    def enable_memcache(self, release=None):
        """Determine if memcache should be enabled on the local unit

        @param release: release of OpenStack currently deployed
        @returns boolean Whether memcache should be enabled
        """
        if not release:
            release = os_utils.get_os_codename_install_source(
                self.config['openstack-origin'])
        if release not in os_utils.OPENSTACK_RELEASES:
            return ValueError("Unkown release {}".format(release))
        return (os_utils.OPENSTACK_RELEASES.index(release) >=
                os_utils.OPENSTACK_RELEASES.index('mitaka'))

    def token_cache_pkgs(self, release=None):
        """Determine additional packages needed for token caching

        @param release: release of OpenStack currently deployed
        @returns List of package to enable token caching
        """
        packages = []
        if self.enable_memcache(release=release):
            packages.extend(['memcached', 'python-memcache'])
        return packages

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

    @property
    def all_packages(self):
        """List of packages to be installed

        @return ['pkg1', 'pkg2', ...]
        """
        return (super(OpenStackAPICharm, self).all_packages +
                self.token_cache_pkgs())

    @property
    def all_snaps(self):
        """List of snaps to be installed

        @return ['snap1', 'snap2', ...]
        """
        return super().all_snaps

    @property
    def full_restart_map(self):
        """Map of services to be restarted if a file changes

        @return {
                    'file1': ['svc1', 'svc3'],
                    'file2': ['svc2', 'svc3'],
                    ...
                }
        """
        _restart_map = super(OpenStackAPICharm, self).full_restart_map.copy()
        if self.enable_memcache():
            _restart_map[self.MEMCACHE_CONF] = ['memcached']
        return _restart_map


class HAOpenStackCharm(OpenStackAPICharm):

    abstract_class = True

    HAPROXY_CONF = '/etc/haproxy/haproxy.cfg'
    ha_resources = []

    def __init__(self, **kwargs):
        super(HAOpenStackCharm, self).__init__(**kwargs)
        self.set_haproxy_stat_password()

    @property
    def apache_ssl_vhost_file(self):
        """Apache vhost for SSL termination

        :returns: string
        """
        return APACHE_SSL_VHOST

    def enable_apache_ssl_vhost(self):
        """Enable Apache vhost for SSL termination

        Enable Apache vhost for SSL termination if vhost exists and it is not
        curently enabled
        """
        if not os.path.exists(self.apache_ssl_vhost_file):
            open(self.apache_ssl_vhost_file, 'a').close()

        check_enabled = subprocess.call(
            ['a2query', '-s', 'openstack_https_frontend'])
        if check_enabled:
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
        _packages = super(HAOpenStackCharm, self).all_packages
        if self.haproxy_enabled():
            _packages.append('haproxy')
        if not os_utils.snap_install_requested():
            if self.apache_enabled():
                _packages.append('apache2')
        return _packages

    @property
    def all_snaps(self):
        """List of snaps to be installed

        @return ['snap1', 'snap2', ...]
        """
        _snaps = super().all_snaps
        return _snaps

    @property
    def full_restart_map(self):
        """Map of services to be restarted if a file changes

        @return {
                    'file1': ['svc1', 'svc3'],
                    'file2': ['svc2', 'svc3'],
                    ...
                }
        """
        _restart_map = super(HAOpenStackCharm, self).full_restart_map
        if self.haproxy_enabled():
            _restart_map[self.HAPROXY_CONF] = ['haproxy']
        if os_utils.snap_install_requested():
            # TODO(coreycb): add nginx config/service for ssl vhost
            pass
        else:
            if self.apache_enabled():
                _restart_map[self.apache_ssl_vhost_file] = ['apache2']
        return _restart_map

    def apache_enabled(self):
        """Determine if apache is being used

        @return True if apache is being used"""
        if os_utils.snap_install_requested():
            return False
        else:
            return (self.get_state('ssl.enabled') or
                    self.get_state('ssl.requested'))

    def nginx_ssl_enabled(self):
        """Determine if nginx is being used

        @return True if nginx is being used"""
        if os_utils.snap_install_requested():
            return (self.get_state('ssl.enabled') or
                    self.get_state('ssl.requested'))
        else:
            return False

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
        if os_utils.snap_install_requested():
            return
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
        if os_utils.snap_install_requested():
            ssl_dir = '/var/snap/{snap_name}/etc/nginx/ssl'.format(
                snap_name=self.primary_snap)
        else:
            ssl_dir = os.path.join('/etc/apache2/ssl/', self.name)

        if not cn:
            cn = os_ip.resolve_address(endpoint_type=os_ip.INTERNAL)
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
                'ca': (self.config_defined_ssl_ca.decode('utf-8')
                       if self.config_defined_ssl_ca else None),
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

    def _get_b64decode_for(self, param):
        config_value = self.config.get(param)
        if config_value:
            return base64.b64decode(config_value)
        return None

    @property
    @hookenv.cached
    def config_defined_ssl_key(self):
        return self._get_b64decode_for('ssl_key')

    @property
    @hookenv.cached
    def config_defined_ssl_cert(self):
        return self._get_b64decode_for('ssl_cert')

    @property
    @hookenv.cached
    def config_defined_ssl_ca(self):
        return self._get_b64decode_for('ssl_ca')

    @property
    def rabbit_client_cert_dir(self):
        return '/var/lib/charm/{}'.format(hookenv.service_name())

    @property
    def rabbit_cert_file(self):
        return '{}/rabbit-client-ca.pem'.format(self.rabbit_client_cert_dir)

    def configure_ssl(self, keystone_interface=None):
        """Configure SSL certificates and keys

        NOTE(AJK): This function tries to minimise the work it does,
        particularly with writing files and restarting apache.

        @param keystone_interface KeystoneRequires class
        """
        keystone_interface = (
            reactive.RelationBase
            .from_state('identity-service.available.ssl') or
            reactive.RelationBase
            .from_state('identity-service.available.ssl_legacy'))
        ssl_objects = self.get_certs_and_keys(
            keystone_interface=keystone_interface)
        with is_data_changed('configure_ssl.ssl_objects',
                             ssl_objects) as changed:
            if ssl_objects:
                if changed:
                    for ssl in ssl_objects:
                        self.set_state('ssl.requested', True)
                        self.configure_cert(
                            ssl['cert'], ssl['key'], cn=ssl['cn'])
                        self.configure_ca(ssl['ca'])

                    if not os_utils.snap_install_requested():
                        self.configure_apache()

                    self.remove_state('ssl.requested')
                self.set_state('ssl.enabled', True)
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
        # TODO(jamespage): work this out for snap based installations
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
        """Update peers in the cluster about the addresses that this unit
        holds.

        NOTE(AJK): This uses the helper is_data_changed() to track whether this
        has already been done, and doesn't re-advertise the changes if nothing
        has changed.

        @param cluster: the interface object for the cluster relation
        """
        laddrs = []
        for addr_type in sorted(os_ip.ADDRESS_MAP.keys()):
            cidr = self.config.get(os_ip.ADDRESS_MAP[addr_type]['config'])
            laddr = ch_ip.get_address_in_network(cidr)
            laddrs.append((addr_type, laddr))
        with is_data_changed('update_peers.laddrs', laddrs) as changed:
            if changed:
                for (addr_type, laddr) in laddrs:
                    cluster.set_address(
                        os_ip.ADDRESS_MAP[addr_type]['binding'],
                        laddr)
