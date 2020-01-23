import base64
import contextlib
import os
import random
import re
import shutil
import string
import subprocess

import charmhelpers.contrib.hahelpers.cluster as ch_cluster
import charmhelpers.contrib.network.ip as ch_ip
import charmhelpers.contrib.openstack.utils as os_utils
import charmhelpers.contrib.openstack.ha as os_ha
import charmhelpers.contrib.openstack.ha.utils as os_ha_utils
import charmhelpers.contrib.openstack.cert_utils as cert_utils
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
    is_data_changed,
)
import charms_openstack.adapters as os_adapters
import charms_openstack.ip as os_ip

VIP_KEY = "vip"
CIDR_KEY = "vip_cidr"
IFACE_KEY = "vip_iface"
DNSHA_KEY = "dns-ha"
APACHE_SSL_VHOST = '/etc/apache2/sites-available/openstack_https_frontend.conf'
SYSTEM_CA_CERTS = '/etc/ssl/certs/ca-certificates.crt'
SNAP_PATH_PREFIX_FORMAT = '/var/snap/{}/common'
SNAP_CA_CERTS = SNAP_PATH_PREFIX_FORMAT + '/etc/ssl/certs/ca-certificates.crt'


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

    # List of packages to purge
    purge_packages = []

    # Python version used to execute installed workload
    python_version = 2

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

    # A dictionary of:
    # {
    #     '/etc/init.d/executable': 0o755,
    #     '/var/lib/super-secret-file': 0o600,
    # }
    permission_override_map = {}

    # The list of required services that are checked for assess_status
    # e.g. required_relations = ['identity-service', 'shared-db']
    required_relations = []

    # The command used to sync the database
    sync_cmd = []

    # The list of services that this charm manages
    services = []

    # package_codenames = {}

    # The name of the repository source configuration option.
    # Useful for charms managing software from UCA and consuming the
    # `openstack` layer directly for re-use of common code, but not being a
    # OpenStack component.
    source_config_key = 'openstack-origin'

    @property
    def resource_install_map(self):
        """Return map of resource names to installation methods

        :returns Map of Juju resource names to installation methods
        :rtype: {'resource_name': f}
        """
        install_map = {
            'driver-deb': self.install_deb
        }
        return install_map

    def install_deb(self, deb):
        """Install the given deb.

        :param deb: Path to deb
        :type: str
        """
        # No attempt is made to deal with dependancies. These should be
        # handled by the charms 'packages' list.
        subprocess.check_call(['dpkg', '-i', deb],
                              env=fetch.get_apt_dpkg_env())

    def install_resources(self):
        """Install Juju application resources
        """
        for resource_name, install_func in self.resource_install_map.items():
            resource = hookenv.resource_get(resource_name)
            if resource:
                install_func(resource)

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
                    self.config[self.source_config_key]
                )
        else:
            if not self.version_package:
                self.version_package = self.packages[0]
            version = fetch.get_upstream_version(
                self.version_package
            )
            if not version:
                version = os_utils.os_release(self.version_package)
        return version

    def run_pause_or_resume(self, action):
        """Helper to enable pause/resume action to be processed."""
        actions = {
            'pause': os_utils.pause_unit,
            'resume': os_utils.resume_unit}
        _services, _ = ch_cluster.get_managed_services_and_ports(
            self.full_service_list,
            [])
        actions[action](self.assess_status, services=_services)

    def pause(self):
        """Pause the charms services."""
        reactive.set_flag("charm.paused")
        self.run_pause_or_resume('pause')

    def resume(self):
        """Resume the charms services."""
        reactive.clear_flag("charm.paused")
        self.run_pause_or_resume('resume')

    def series_upgrade_prepare(self):
        """Prepare to upgrade series"""
        reactive.set_flag("charm.series-upgrading")
        reactive.set_flag("charm.paused")
        os_utils.set_unit_upgrading()
        self.run_pause_or_resume('pause')

    def series_upgrade_complete(self):
        """Prepare to upgrade series"""
        reactive.clear_flag("charm.series-upgrading")
        reactive.clear_flag("charm.paused")
        os_utils.clear_unit_paused()
        os_utils.clear_unit_upgrading()
        self.run_pause_or_resume('resume')

    def enable_services(self):
        """Enable services

        This method is for charm managed enabling of previously disabled
        services where the end user is not involved nor informed about the
        activity.

        Use the pause and resume methods for end user facing activities.
        """
        os_utils.manage_payload_services('resume', self.full_service_list)

    def disable_services(self):
        """Disable services

        This method is for charm managed disabling of services where the end
        user is not involved nor informed about the activity.

        Use the pause and resume methods for end user facing activities.
        """
        os_utils.manage_payload_services('pause', self.full_service_list)

    def restart_services(self):
        """Restart services"""
        os_utils.manage_payload_services('stop', self.full_service_list)
        os_utils.manage_payload_services('start', self.full_service_list)

    def get_certificate_requests(self):
        """Return a dict of certificate requests"""
        return cert_utils.get_certificate_request(
            json_encode=False).get('cert_requests', {})

    @property
    def rabbit_client_cert_dir(self):
        return '/var/lib/charm/{}'.format(self.service_name)

    @property
    def rabbit_cert_file(self):
        return '{}/rabbit-client-ca.pem'.format(self.rabbit_client_cert_dir)

    def get_default_cn(self):
        """Return the default Canonical Name to be used for TLS setup

        :returns: 'canonical_name'
        :rtype: str
        """
        return os_ip.resolve_address(endpoint_type=os_ip.INTERNAL)

    def configure_cert(self, path, cert, key, cn=None):
        """Write out TLS certificate and key to disk.

        :param path: Directory to place files in
        :type path: str
        :param cert: TLS Certificate
        :type cert: str
        :param key: TLS Key
        :type key: str
        :param cn: Canonical name for service
        :type cn: Option[None, str]
        """
        if not cn:
            cn = self.get_default_cn()

        ch_host.mkdir(path=path)
        if cn:
            cert_filename = 'cert_{}'.format(cn)
            key_filename = 'key_{}'.format(cn)
        else:
            cert_filename = 'cert'
            key_filename = 'key'

        ch_host.write_file(path=os.path.join(path, cert_filename),
                           content=cert.encode('utf-8'), group=self.group,
                           perms=0o640)
        ch_host.write_file(path=os.path.join(path, key_filename),
                           content=key.encode('utf-8'), group=self.group,
                           perms=0o640)

    def get_local_addresses(self):
        """Return list of local addresses on each configured network

        For each network return an address the local unit has on that network
        if one exists.

        :returns: [private_addr, admin_addr, public_addr, ...]
        :rtype: List[str]
        """
        addresses = [
            os_utils.get_host_ip(hookenv.unit_get('private-address'))]
        for addr_type in os_ip.ADDRESS_MAP.keys():
            laddr = os_ip.resolve_address(endpoint_type=addr_type)
            if laddr:
                addresses.append(laddr)
        return sorted(list(set(addresses)))

    def get_certs_and_keys(self, keystone_interface=None,
                           certificates_interface=None):
        """Collect TLS config for local endpoints

        TLS keys and certs may come from user specified configuration for this
        charm or they may come directly from the ``certificates`` relation.

        If collecting from ``certificates`` relation there may be a certificate
        and key per endpoint (public, admin etc).

        :param keystone_interface: DEPRECATED Functionality removed.
        :type keystone_interace: Option[None, KeystoneRequires(RelationBase)]
        :param certificates_interface: Certificates interface object
        :type certificates_interface: TlsRequires(Endpoint)
        :returns: [
            {'key': 'key1', 'cert': 'cert1', 'ca': 'ca1', 'cn': 'cn1'}
            {'key': 'key2', 'cert': 'cert2', 'ca': 'ca2', 'cn': 'cn2'}
            ...
        ]
        :rtype: List[Dict[str,str]]
        """
        if self.config_defined_ssl_key and self.config_defined_ssl_cert:
            ssl_artifacts = []
            for ep_type in [os_ip.INTERNAL, os_ip.ADMIN, os_ip.PUBLIC]:
                ssl_artifacts.append({
                    'key': self.config_defined_ssl_key.decode('utf-8'),
                    'cert': self.config_defined_ssl_cert.decode('utf-8'),
                    'ca': (self.config_defined_ssl_ca.decode('utf-8')
                           if self.config_defined_ssl_ca else None),
                    'cn': os_ip.resolve_address(endpoint_type=ep_type)})
            return ssl_artifacts
        elif certificates_interface:
            keys_and_certs = []
            reqs = certificates_interface.get_batch_requests()
            ca = certificates_interface.get_ca()
            chain = certificates_interface.get_chain()
            for cn, data in sorted(reqs.items()):
                cert = data['cert']
                if chain:
                    cert = cert + os.linesep + chain
                keys_and_certs.append({
                    'key': data['key'],
                    'cert': cert,
                    'ca': ca,
                    'chain': chain,
                    'cn': cn})
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

    def configure_ssl(self, keystone_interface=None):
        """DEPRECATED Configure SSL certificates and keys.

        Please use configure_tls insteaad.
        """
        hookenv.log('configure_ssl method is DEPRECATED, please use '
                    'configure_tls instead.', level=hookenv.WARNING)
        self.configure_tls(
            certificates_interface=reactive.endpoint_from_flag(
                'certificates.available'))

    def configure_tls(self, certificates_interface=None):
        """Write out TLS certificate data.

        The reactive handler counterpart in ``layer-openstack`` will make
        sure this helper is called when certificate data is available or
        changed.

        Note that if your charm uses the OpenStackCharm base class directly
        and want to write out client/server certificate and key data you will
        need to override this method and call configure_cert() with a path
        argument appropriate for the service you are implementing a charm
        for.

        :param certificates_interface: A certificates relation
        :type certificates_interface: Option[None, TlsRequires(Endpoint)]
        :returns: List of certificate data as returned by get_certs_and_keys()
        :rtype: List[Dict[str,str]]
        """
        tls_objects = self.get_certs_and_keys(
            certificates_interface=certificates_interface)
        if tls_objects:
            # NOTE(fnordahl): regardless of changes to data we may
            # have other changes we want to apply to the files.
            # (e.g. ownership, permissions)
            #
            # Also note that update_central_cacerts() used in configure_ca()
            # has it's own logic to detect data changes.
            #
            # LP: #1821314
            for tls_object in tls_objects:
                self.configure_ca(tls_object['ca'])
                if 'chain' in tls_object:
                    self.configure_ca(tls_object['chain'], postfix='chain')

        # NOTE(fnordahl): Retaining for in-transition compability with current
        # usage.  The RabbitMQ TLS configuration should be initiated by the
        # layer code.  Given we have non-API services consuming RabbitMQ we
        # should probably move the RabbitMQ reactive handling code down to the
        # ``openstack`` layer too.
        #
        # Will address this in separate review.  LP: #1841912
        amqp_ssl = reactive.endpoint_from_flag('amqp.available.ssl')
        if amqp_ssl:
            self.configure_rabbit_cert(amqp_ssl)

        return tls_objects

    def configure_rabbit_cert(self, rabbit_interface):
        if not os.path.exists(self.rabbit_client_cert_dir):
            os.makedirs(self.rabbit_client_cert_dir)
        with open(self.rabbit_cert_file, 'w') as crt:
            crt.write(rabbit_interface.get_ssl_cert())

    @contextlib.contextmanager
    def update_central_cacerts(self, cert_files, update_certs=True):
        """Update Central certs info if one of cert_files changes"""
        checksums = {path: ch_host.path_hash(path)
                     for path in cert_files}
        yield
        new_checksums = {path: ch_host.path_hash(path)
                         for path in cert_files}
        if checksums != new_checksums and update_certs:
            self.run_update_certs()
            self.install_snap_certs()

    def configure_ca(self, ca_cert, update_certs=True, postfix=''):
        """Write Certificate Authority certificate"""
        # TODO(jamespage): work this out for snap based installations
        name = self.service_name
        if postfix:
            name = '-'.join((name, postfix))
        cert_file = (
            '/usr/local/share/ca-certificates/{}.crt'
            .format(name))
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

    def install_snap_certs(self):
        """Install systems CA certificates for a snap

        Installs the aggregated host system ca-certificates.crt into
        $SNAP_COMMON/etc/ssl/certs for services running within a sandboxed
        snap to consume.

        Snaps should set the REQUESTS_CA_BUNDLE environment variable to
        ensure requests based API calls use the updated system certs.
        """
        if (os_utils.snap_install_requested() and
                os.path.exists(SYSTEM_CA_CERTS)):
            ca_certs = SNAP_CA_CERTS.format(self.primary_snap)
            ch_host.mkdir(os.path.dirname(ca_certs))
            shutil.copyfile(SYSTEM_CA_CERTS, ca_certs)

    @property
    def service_name(self):
        return hookenv.service_name()

    @property
    def full_service_list(self):
        """Copy of full list of services managed

        Including those automatically added by framework that charm author may
        have no knowledge about.

        :returns: Full list of services managed by charm
        :rtype: List[str]
        """
        return self.services[:]


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

    # These can be overridden in the derived charm class to allow specialism of
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
                self.config[self.source_config_key])
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
            if self.python_version == 2:
                packages.extend(['memcached', 'python-memcache'])
            else:
                packages.extend(['memcached', 'python3-memcache'])
        return packages

    def get_amqp_credentials(self):
        """Provide the default amqp username and vhost as a tuple.

        This needs to be overridden in a derived class to provide the username
        and vhost to the amqp interface IF the default amqp handlers are being
        used.
        :returns (username, host): two strings to send to the amqp provider.
        """
        raise RuntimeError(
            "get_amqp_credentials() needs to be overridden in the derived "
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
            "get_database_setup() needs to be overridden in the derived "
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

    @property
    def full_service_list(self):
        """Copy of full list of services managed

        Including those automatically added by framework that charm author may
        have no knowledge about.

        :returns: Full list of services managed by charm
        :rtype: List[str]
        """
        services = super().full_service_list
        if self.enable_memcache():
            services.append('memcached')
        return services


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
            'dnsha': self._add_dnsha_config,
        }
        if self.ha_resources:
            for res_type in self.ha_resources:
                RESOURCE_TYPES[res_type](hacluster)
            hacluster.bind_resources(iface=self.config[IFACE_KEY])

    def _add_ha_vips_config(self, hacluster):
        """Add a VirtualIP object for each user specified vip to self.resources

        @param hacluster instance of interface class HAClusterRequires
        """
        if not self.config.get(VIP_KEY):
            return
        for vip in self.config[VIP_KEY].split():
            iface, netmask, fallback = os_ha_utils.get_vip_settings(vip)
            if fallback:
                hacluster.add_vip(
                    self.name,
                    vip,
                    iface,
                    netmask)
            else:
                hacluster.add_vip(self.name, vip)
                if iface:
                    # Remove vip resource using old raw nic name.
                    old_vip_key = 'res_{}_{}_vip'.format(self.name, iface)
                    hacluster.delete_resource(old_vip_key)

    def _add_ha_haproxy_config(self, hacluster):
        """Add a InitService object for haproxy to self.resources

        @param hacluster instance of interface class HAClusterRequires
        """
        hacluster.add_init_service(self.name, 'haproxy')

    def _add_dnsha_config(self, hacluster):
        """Add a DNSHA object to self.resources

        @param hacluster instance of interface class HAClusterRequires
        """
        if not self.config.get(DNSHA_KEY):
            return
        settings = ['os-admin-hostname', 'os-internal-hostname',
                    'os-public-hostname', 'os-access-hostname']

        for setting in settings:
            hostname = self.config.get(setting)
            if hostname is None:
                hookenv.log(
                    'DNS HA: Hostname setting {} is None. Ignoring.'.format(
                        setting),
                    hookenv.DEBUG)
                continue
            m = re.search('os-(.+?)-hostname', setting)
            if m:
                endpoint_type = m.group(1)
                # resolve_address's ADDRESS_MAP uses 'int' not 'internal'
                if endpoint_type == 'internal':
                    endpoint_type = 'int'
            else:
                msg = (
                    'Unexpected DNS hostname setting: {}. Cannot determine '
                    'endpoint_type name'.format(setting))
                hookenv.status_set('blocked', msg)
                raise os_ha.DNSHAException(msg)
            ip = os_ip.resolve_address(
                endpoint_type=endpoint_type,
                override=False)
            hacluster.add_dnsha(self.name, ip, hostname, endpoint_type)

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
        for module in ['ssl', 'proxy', 'proxy_http', 'headers']:
            check_enabled = subprocess.call(['a2query', '-m', module])
            if check_enabled != 0:
                subprocess.check_call(['a2enmod', module])
                restart = True
        if restart:
            ch_host.service_restart('apache2')

    def configure_tls(self, certificates_interface=None):
        """Configure TLS certificates and keys

        NOTE(AJK): This function tries to minimise the work it does,
        particularly with writing files and restarting apache.

        :param certificates_interface: certificates relation endpoint
        :type certificates_interface: TlsRequires(Endpoint) object
        """
        # this takes care of writing out the CA certificate
        tls_objects = super().configure_tls(
            certificates_interface=certificates_interface)
        with is_data_changed(
                'configure_ssl.ssl_objects', tls_objects) as changed:
            if tls_objects:
                # NOTE(fnordahl): regardless of changes to data we may
                # have other changes we want to apply to the files.
                # (e.g. ownership, permissions)
                #
                # Also note that c-h.host.write_file used in configure_cert()
                # has it's own logic to detect data changes.
                #
                # LP: #1821314
                for tls_object in tls_objects:
                    self.set_state('ssl.requested', True)
                    if os_utils.snap_install_requested():
                        path = ('/var/snap/{snap_name}/common/etc/nginx/ssl'
                                .format(snap_name=self.primary_snap))
                    else:
                        path = os.path.join('/etc/apache2/ssl/', self.name)
                    self.configure_cert(
                        path,
                        tls_object['cert'],
                        tls_object['key'],
                        cn=tls_object['cn'])
                    cert_utils.create_ip_cert_links(
                        os.path.join('/etc/apache2/ssl/', self.name))
                    if not os_utils.snap_install_requested() and changed:
                        self.configure_apache()
                        ch_host.service_reload('apache2')

                    self.remove_state('ssl.requested')
                    self.set_state('ssl.enabled', True)
            else:
                self.set_state('ssl.enabled', False)

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
            laddr = ch_ip.get_relation_ip(
                os_ip.ADDRESS_MAP[addr_type]['binding'],
                cidr)
            laddrs.append((addr_type, laddr))
        with is_data_changed('update_peers.laddrs', laddrs) as changed:
            if changed:
                for (addr_type, laddr) in laddrs:
                    cluster.set_address(
                        os_ip.ADDRESS_MAP[addr_type]['binding'],
                        laddr)

    @property
    def full_service_list(self):
        """Copy of full list of services managed

        Including those automatically added by framework that charm author may
        have no knowledge about.

        :returns: Full list of services managed by charm
        :rtype: List[str]
        """
        services = super().full_service_list
        if self.haproxy_enabled():
            services.append('haproxy')
        return services


class CinderStoragePluginCharm(OpenStackCharm):

    abstract_class = True

    # The name of the charm (for printing, etc.)
    name = ''

    # List of packages to install
    # XXX execd_preinstall
    packages = []

    version_package = ''
    # The list of required services that are checked for assess_status
    # e.g. required_relations = ['identity-service', 'shared-db']
    required_relations = []

    # A dictionary of:
    # {
    #    'config.file': ['list', 'of', 'services', 'to', 'restart'],
    #    'config2.file': ['more', 'services'],
    # }
    # The files that for the keys of the dict are monitored and if the file
    # changes the corresponding services are restarted
    # XXX This is more involved in the tradioional charm so we're
    # probably missing something herw!
    restart_map = {}

    # first_release = this is the first release in which this charm works
    release = ''

    def install(self):
        """Install packages and resources."""
        # Install PPA if one has been defined.
        if self.config.get('driver-source'):
            fetch.add_source(
                self.config.get('driver-source'),
                key=self.config.get('driver-key'))
            fetch.apt_update()
        super().install()
        # All package install to run first incase payload has deps.
        self.install_resources()
        self.assess_status()

    def upgrade_charm(self):
        """Run default upgrade_charm method and reinstall resources"""
        super().upgrade_charm()
        # A change in resources triggers an upgrade-charm
        self.install_resources()

    @property
    def stateless(self):
        raise NotImplementedError()

    def cinder_configuration(self):
        raise NotImplementedError()

    def send_storage_backend_data(self):
        cbend = reactive.endpoint_from_flag('storage-backend.connected')
        cbend.configure_principal(
            backend_name=self.service_name,
            configuration=self.cinder_configuration(),
            stateless=self.stateless)
        # Add an assess status which will be picked up later by the atexit()
        # handler.
        self.assess_status()
