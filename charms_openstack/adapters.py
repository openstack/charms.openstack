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

"""Adapter classes and utilities for use with Reactive interfaces"""
from __future__ import absolute_import

import collections
import itertools
import re
import weakref

import charms.reactive as reactive
import charms.reactive.bus
import charmhelpers.contrib.hahelpers.cluster as ch_cluster
import charmhelpers.contrib.network.ip as ch_ip
import charmhelpers.contrib.openstack.context as ch_context
import charmhelpers.contrib.openstack.utils as ch_utils
import charmhelpers.core.hookenv as hookenv
import charmhelpers.core.host as ch_host
import charms_openstack.ip as os_ip

ADDRESS_TYPES = os_ip.ADDRESS_MAP.keys()

# handle declarative adapter properties using a decorator and simple functions

# Hold the custom adapter properties somewhere!
_custom_adapter_properties = {}


def adapter_property(interface_name):
    """Decorator to take the interface name and add a custom property.
    These are used to generate custom Adapter classes automatically for the
    charm author which are then plugged into the class.  The adapter class is
    built using a different function.

    :param interface_name: the name of the interface to add the property to
    """
    def wrapper(f):
        property_name = f.__name__
        if interface_name not in _custom_adapter_properties:
            _custom_adapter_properties[interface_name] = {}
        if property_name in _custom_adapter_properties[interface_name]:
            raise RuntimeError(
                "Property name '{}' used more than once for '{} interface?"
                .format(property_name, interface_name))
        _custom_adapter_properties[interface_name][property_name] = f
        return f
    return wrapper


# declaring custom configuration properties:

# Hold the custom configuration adapter properties somewhere!
_custom_config_properties = {}


def config_property(f):
    """Decorator to add a custom configuration property.

    These are used to generate a custom ConfigurationAdapter for use when
    automatically creating a Charm class

    :param f: the function passed as part of the @decorator syntax
    """
    property_name = f.__name__
    if property_name in _custom_config_properties:
        raise RuntimeError(
            "Property name '{}' used more than once for configuration?"
            .format(property_name))
    _custom_config_properties[property_name] = f
    return f

##


class OpenStackRelationAdapter(object):
    """
    Base adapter class for all OpenStack related adapters.
    """

    interface_type = None
    """
    The generic type of the interface the adapter is wrapping.
    """

    def __init__(self, relation=None, accessors=None, relation_name=None):
        """Class will usually be initialised using the 'relation' option to
           pass in an instance of a interface class. If there is no relation
           class yet available then 'relation_name' can be used instead.

           :param relation: Instance of an interface class
           :param accessors: List of accessible interfaces properties
           :param relation_name: String name of relation
        """
        self.relation = relation
        if relation and relation_name:
            raise ValueError('Cannot speciiy relation and relation_name')
        if relation:
            self.accessors = accessors or []
            self._setup_properties()
        else:
            self._relation_name = relation_name

    @property
    def relation_name(self):
        """
        Name of the relation this adapter is handling.
        """
        if self.relation:
            return self.relation.relation_name
        else:
            return self._relation_name

    def _setup_properties(self):
        """
        Setup property based accessors for an interfaces
        auto accessors

        Note that the accessor is dynamic as each access calls the underlying
        getattr() for each property access.
        """
        self.accessors.extend(self.relation.auto_accessors)
        for field in self.accessors:
            meth_name = field.replace('-', '_')
            # Get the relation property dynamically
            # Note the additional lambda name: is to create a closure over
            # meth_name so that a new 'name' gets created for each loop,
            # otherwise the same variable meth_name is referenced in each of
            # the internal lambdas.  i.e. this is (lambda x: ...)(value)
            setattr(self.__class__,
                    meth_name,
                    (lambda name: property(
                        lambda self: getattr(
                            self.relation, name)()))(meth_name))


class RabbitMQRelationAdapter(OpenStackRelationAdapter):
    """
    Adapter for the RabbitMQRequires relation interface.
    """

    interface_type = "messaging"

    def __init__(self, relation):
        add_accessors = ['vhost', 'username']
        super(RabbitMQRelationAdapter, self).__init__(relation, add_accessors)

    @property
    def host(self):
        """
        Hostname that should be used to access RabbitMQ.
        """
        if self.vip:
            return self.vip
        else:
            return self.private_address

    @property
    def hosts(self):
        """
        Comma separated list of hosts that should be used
        to access RabbitMQ.
        """
        hosts = self.relation.rabbitmq_hosts()
        if len(hosts) > 1:
            return ','.join(hosts)
        else:
            return None

    @property
    def ssl_data_complete(self):
        return self.relation.ssl_data_complete()

    @property
    def ssl_ca_file(self):
        return '/var/lib/charm/{}/rabbit-client-ca.pem'.format(
            hookenv.service_name())


class PeerHARelationAdapter(OpenStackRelationAdapter):
    """
    Adapter for cluster relation of nodes of the same service
    """

    interface_type = "cluster"

    def __init__(self, relation=None, relation_name=None):
        """Map of local units addresses for each address type

           :param relation: Instance of openstack-ha relation
           :param relation_name: Name of relation if openstack-ha relation is
                                 not available e.g. 'cluster'

           NOTE: This excludes private-address
           @return dict of backends and networks for local unit e.g.
               {'this_unit_admin_addr': {
                    'backends': {
                        'this_unit-1': 'this_unit_admin_addr'},
                    'network': 'this_unit_admin_addr/admin_netmask'},
                'this_unit_internal_addr': {
                    'backends': {
                        'this_unit-1': 'this_unit_internal_addr'},
                    'network': 'this_unit_internal_addr/internal_netmask'},
                'this_unit_public_addr': {
                    'backends': {
                        'this_unit-1': 'this_unit_public_addr'},
                    'network': 'this_unit_public_addr/public_netmask'}}
        """
        super(PeerHARelationAdapter, self).__init__(
            relation=relation,
            relation_name=relation_name)
        self.config = hookenv.config()
        self.api_config_adapter = APIConfigurationAdapter()
        self.local_address = self.api_config_adapter.local_address
        self.local_unit_name = self.api_config_adapter.local_unit_name
        # Note(AJK) - bug #1698814 - cluster_hosts needs to be ordered so that
        # re-writes with no changed data don't cause a restart (dictionaries
        # are 'randomly' ordered)
        self.cluster_hosts = collections.OrderedDict()
        if relation:
            self.add_network_split_addresses()
            self.add_default_addresses()

    @property
    def internal_addresses(self):
        """Return list of internal addresses of this unit and peers

           Return list of internal addresses of this unit and peers. If no
           internal address cidr has been set return private addresses.

           @return list [ip1, ip2, ...]
        """
        cfg_opt = os_ip.ADDRESS_MAP[os_ip.INTERNAL]['config']
        int_net = self.config.get(cfg_opt)
        laddr = ch_ip.get_address_in_network(int_net) or self.local_address
        try:
            hosts = sorted(
                list(self.cluster_hosts[laddr]['backends'].values()))
        except KeyError:
            hosts = [laddr]
        return hosts

    @property
    def single_mode_map(self):
        """Return map of local addresses only if this is a single node cluster

           @return dict of local address info e.g.
               {'cluster_hosts':
                   {'this_unit_private_addr': {
                        'backends': {
                            'this_unit-1': 'this_unit_private_addr'},
                        'network': 'this_unit_private_addr/private_netmask'},
                'internal_addresses': ['intaddr']}
        """
        relation_info = {}
        try:
            cluster_relid = hookenv.relation_ids('cluster')[0]
            if not hookenv.related_units(relid=cluster_relid):
                relation_info = {
                    'cluster_hosts': self.local_default_addresses(),
                    'internal_addresses': self.internal_addresses,
                }
                net_split = self.local_network_split_addresses()
                for key in net_split.keys():
                    relation_info['cluster_hosts'][key] = net_split[key]
        except IndexError:
            pass
        return relation_info

    def local_network_split_addresses(self):
        """Map of local units addresses for each address type

           NOTE: This excludes private-address
           @return dict of backends and networks for local unit e.g.
               {'this_unit_admin_addr': {
                    'backends': {
                        'this_unit-1': 'this_unit_admin_addr'},
                    'network': 'this_unit_admin_addr/admin_netmask'},
                'this_unit_internal_addr': {
                    'backends': {
                        'this_unit-1': 'this_unit_internal_addr'},
                    'network': 'this_unit_internal_addr/internal_netmask'},
                'this_unit_public_addr': {
                    'backends': {
                        'this_unit-1': 'this_unit_public_addr'},
                    'network': 'this_unit_public_addr/public_netmask'}}
        """
        config = hookenv.config()
        _cluster_hosts = {}
        for addr_type in ADDRESS_TYPES:
            cfg_opt = os_ip.ADDRESS_MAP[addr_type]['config']
            laddr = ch_ip.get_address_in_network(config.get(cfg_opt))
            if laddr:
                netmask = ch_ip.get_netmask_for_address(laddr)
                _cluster_hosts[laddr] = {
                    'network': "{}/{}".format(laddr, netmask),
                    'backends': collections.OrderedDict(
                        [(self.local_unit_name, laddr)])}
        return _cluster_hosts

    def local_default_addresses(self):
        """Map of local units private address

           @return dict of private address info local unit e.g.
               {'this_unit_private_addr': {
                    'backends': {
                        'this_unit-1': 'this_unit_private_addr'},
                    'network': 'this_unit_private_addr/private_netmask'}}

        """
        netmask = ch_ip.get_netmask_for_address(self.local_address)
        _local_map = {
            self.local_address: {
                'network': "{}/{}".format(self.local_address, netmask),
                'backends': collections.OrderedDict(
                    [(self.local_unit_name, self.local_address)])}}
        return _local_map

    def add_network_split_addresses(self):
        """Populate cluster_hosts with addresses of this unit and its
           peers on each address type

           @return None
        """
        for addr_type in ADDRESS_TYPES:
            cfg_opt = os_ip.ADDRESS_MAP[addr_type]['config']
            laddr = ch_ip.get_address_in_network(self.config.get(cfg_opt))
            if laddr:
                self.cluster_hosts[laddr] = \
                    self.local_network_split_addresses()[laddr]
                key = '{}-address'.format(
                    os_ip.ADDRESS_MAP[addr_type]['binding'])
                for _unit, _laddr in self.relation.ip_map(address_key=key):
                    if _laddr:
                        self.cluster_hosts[laddr]['backends'][_unit] = _laddr

    def add_default_addresses(self):
        """Populate cluster_hosts with private-address of this unit and its
           peers

           @return None
        """
        self.cluster_hosts[self.local_address] = \
            self.local_default_addresses()[self.local_address]
        for _unit, _laddr in self.relation.ip_map():
            self.cluster_hosts[self.local_address]['backends'][_unit] = _laddr


class DatabaseRelationAdapter(OpenStackRelationAdapter):
    """
    Adapter for the Database relation interface.
    """

    interface_type = "database"

    def __init__(self, relation):
        add_accessors = ['password', 'username', 'database']
        super(DatabaseRelationAdapter, self).__init__(relation, add_accessors)

    @property
    def host(self):
        """
        Hostname that should be used to access a database.
        """
        return self.relation.db_host()

    @property
    def type(self):
        return 'mysql'

    def get_uri(self, prefix=None):
        if prefix:
            uri = 'mysql://{}:{}@{}/{}'.format(
                self.relation.username(prefix=prefix),
                self.relation.password(prefix=prefix),
                self.host,
                self.relation.database(prefix=prefix),
            )
        else:
            uri = 'mysql://{}:{}@{}/{}'.format(
                self.username,
                self.password,
                self.host,
                self.database,
            )
        try:
            if self.ssl_ca:
                uri = '{}?ssl_ca={}'.format(uri, self.ssl_ca)
                if self.ssl_cert:
                    uri = ('{}&ssl_cert={}&ssl_key={}'
                           .format(uri, self.ssl_cert, self.ssl_key))
        except AttributeError:
            # ignore ssl_ca or ssl_cert if not available
            pass
        return uri

    @property
    def uri(self):
        return self.get_uri()


def make_default_options(base_cls=None, charm_instance=None):
    """Create a default, customised ConfigurationAdapter, or derived class
    (based on the base_cls) using any custom properties that might have been
    made.

    If base_cls is None, the the default ConfigurationAdapter will be used.

    :param base_cls: a ConfigurationAdapter or derived class
    :param charm_instance: the charm instance to plug into the options.
    """
    return make_default_configuration_adapter_class(
        base_cls=base_cls,
        custom_properties=_custom_config_properties)(
            charm_instance=charm_instance)


def make_default_configuration_adapter_class(base_cls=None,
                                             custom_properties=None):
    """Create a default configuration adapter, using the base type specified
    and any customer configuration properties.

    This is called by the charm creation metaclass when 'bringing' up the class
    if no configuration adapter has been specified in the adapters_class

    :param base_cls: a ConfigurationAdapter derived class; or None
    :param custom_properties: the name:function for the properties to set.
    """
    base_cls = base_cls or ConfigurationAdapter
    # if there are no custom properties, just return the base_cls
    if not custom_properties:
        return base_cls
    # turns the functions into properties on the class
    properties = {n: property(f) for n, f in custom_properties.items()}
    # build a custom class with the custom properties
    return type('DefaultConfigurationAdapter', (base_cls, ), properties)


class ConfigurationAdapter(object):
    """
    Configuration Adapter which provides python based access
    to all configuration options for the current charm.

    It also holds a weakref to the instance of the OpenStackCharm derived class
    that it is associated with.  This is so that methods on the configuration
    adapter can query the charm class for global config (e.g. service_name).


    The configuration items from Juju are copied over and the '-' are replaced
    with '_'.  This allows them to be used directly on the instance.
    """

    def __init__(self, charm_instance=None):
        """Create a ConfigurationAdapter (or derived) class.

        :param charm_instance: the instance of the OpenStackCharm derived
            class.
        """
        self._charm_instance_weakref = None
        if charm_instance is not None:
            self._charm_instance_weakref = weakref.ref(charm_instance)
        # copy over (statically) the items of the charms Juju configuration
        for k, v in hookenv.config().items():
            k = k.replace('-', '_')
            setattr(self, k, v)

    @property
    def charm_instance(self):
        """Return the reference to the charm_instance or return None"""
        if self._charm_instance_weakref:
            return self._charm_instance_weakref()
        return None

    @property
    def application_name(self):
        """Return the name of the deployed charm"""
        return hookenv.service_name()


class APIConfigurationAdapter(ConfigurationAdapter):
    """This configuration adapter extends the base class and adds properties
    common across most OpenstackAPI services.
    """

    def __init__(self, port_map=None, service_name=None, charm_instance=None):
        """
        Note passing port_map and service_name is deprecated, but supported for
        backwards compatibility.  The port_map and service_name can be obtained
        from the self.charm_instance weak reference.
        :param  port_map: Map containing service names and the ports used e.g.
                port_map = {
                        'svc1': {
                        'admin': 9001,
                        'public': 9001,
                        'int': 9001,
                    },
                        'svc2': {
                        'admin': 9002,
                        'public': 9002,
                        'int': 9002,
                    },
                }
        :param service_name: Name of service being deployed
        :param charm_instance: a charm instance that will be passed to the base
            constructor
        """
        super(APIConfigurationAdapter, self).__init__(
            charm_instance=charm_instance)
        if port_map is not None:
            hookenv.log(
                "DEPRECATION: should not use port_map parameter in "
                "APIConfigurationAdapter.__init__()", level=hookenv.WARNING)
            self.port_map = port_map
        elif self.charm_instance is not None:
            self.port_map = self.charm_instance.api_ports
        else:
            self.port_map = None
        if service_name is not None:
            hookenv.log(
                "DEPRECATION: should not use service_name parameter in "
                "APIConfigurationAdapter.__init__()", level=hookenv.WARNING)
            self.service_name = service_name
        elif self.charm_instance is not None:
            self.service_name = self.charm_instance.name
        else:
            self.service_name = None
        self.__network_addresses = None

    @property
    def network_addresses(self):
        """Return the network_addresses as a property for a consuming template.

        See APIConfigurationAdapter.get_network_addresses() for detail on the
        return type.
        """
        # cache and lazy resolve the network addresses - also helps with unit
        # testing
        if self.__network_addresses is None:
            self.__network_addresses = self.get_network_addresses()
        return self.__network_addresses

    @property
    def external_ports(self):
        """Return ports the service will be accessed on

        The self.port_map is a dictionary of dictionaries, where the ports are
        two levels deep (the leaves). This returns a set() of those ports.

        @return set of ports service can be accessed on
        """
        # the map take the first list of dictionaries to extract the 2nd level
        # of values.
        return set(itertools.chain(*map(lambda x: x.values(),
                                        self.port_map.values())))

    @property
    def ipv6_mode(self):
        """Return if charm should enable IPv6

        @return True if user has requested ipv6 support otherwise False
        """
        return getattr(self, 'prefer_ipv6', False)

    @property
    def local_address(self):
        """Return remotely accessible address of charm (not localhost)

        @return True if user has requested ipv6 support otherwise False
        """
        if self.ipv6_mode:
            addr = ch_ip.get_ipv6_addr(exc_list=[self.vip])[0]
        else:
            addr = ch_utils.get_host_ip(
                hookenv.unit_get('private-address'))
        return addr

    @property
    def local_unit_name(self):
        """
        @return local unit name
        """
        return hookenv.local_unit().replace('/', '-')

    @property
    def local_host(self):
        """Return localhost address depending on whether IPv6 is enabled

        @return localhost ip address
        """
        return 'ip6-localhost' if self.ipv6_mode else '127.0.0.1'

    @property
    def haproxy_host(self):
        """Return haproxy bind address depending on whether IPv6 is enabled

        @return address
        """
        return '::' if self.ipv6_mode else '0.0.0.0'

    @property
    def haproxy_stat_port(self):
        """Port to listen on to access haproxy statistics

        @return port
        """
        return '8888'

    @property
    def haproxy_stat_password(self):
        """Password for accessing haproxy statistics

        @return password
        """
        return charms.reactive.bus.get_state('haproxy.stat.password')

    @property
    def service_ports(self):
        """Dict of service names and the ports they listen on

        @return {'svc1': ['portA', 'portB'], 'svc2': ['portC', 'portD'], ...}
        """
        # Note(AJK) - ensure that service ports is always in the same order
        service_ports = collections.OrderedDict()
        if self.port_map:
            for service in sorted(self.port_map.keys()):
                port_types = sorted(list(self.port_map[service].keys()))
                for port_type in port_types:
                    listen_port = self.port_map[service][port_type]
                    key = '{}_{}'.format(service, port_type)
                    used_ports = [v[0] for v in service_ports.values()]
                    if listen_port in used_ports:
                        hookenv.log("Not adding haproxy listen stanza for {} "
                                    "port is already in use".format(key),
                                    level=hookenv.WARNING)
                        continue
                    service_ports[key] = [
                        self.port_map[service][port_type],
                        ch_cluster.determine_apache_port(
                            self.port_map[service][port_type],
                            singlenode_mode=True)]

        return service_ports

    @property
    def apache_enabled(self):
        """Whether apache is being used for this service

        @return True if apache2 os being used for this service
        """
        return charms.reactive.bus.get_state('ssl.enabled')

    @property
    def ssl(self):
        """Whether SSL is being used for this service

        @return True is SSL has been enable
        """
        return charms.reactive.bus.get_state('ssl.enabled')

    def determine_service_port(self, port):
        """Calculate port service should use given external port

        Haproxy fronts connections for a service and may pass connections to
        Apache for SSL termination. Is Apache is being used:
            Haproxy listens on N
            Apache listens on N-10
            Service listens on N-20
        else
            Haproxy listens on N
            Service listens on N-10

        :param int port: port service uses for external connections
        @return int port: port backend service should use
        """
        i = 10
        if self.apache_enabled:
            i = 20
        return (port - i)

    @property
    def service_listen_info(self):
        """Dict of service names and attributes for backend to listen on

        @return {
                    'svc1': {
                        'proto': 'http',
                        'ip': '10.0.0.10',
                        'port': '8080',
                        'url': 'http://10.0.0.10:8080},
                    'svc2': {
                        'proto': 'https',
                        'ip': '10.0.0.20',
                        'port': '8443',
                        'url': 'https://10.0.0.20:8443},
                ...

        """
        info = {}
        ip = self.local_host if self.apache_enabled else self.local_address
        if self.port_map:
            for service in self.port_map.keys():
                key = service.replace('-', '_')
                info[key] = {
                    'proto': 'http',
                    'ip': ip,
                    'port': self.determine_service_port(
                        self.port_map[service]['admin'])}
                for port_type in self.port_map[service].keys():
                    port_key = '{}_port'.format(port_type)
                    info[key][port_key] = self.determine_service_port(
                        self.port_map[service][port_type])
                info[key]['url'] = '{proto}://{ip}:{port}'.format(**info[key])
        return info

    @property
    def external_endpoints(self):
        """Dict of service names and attributes that clients use to connect

        @return {
                    'svc1': {
                        'proto': 'http',
                        'ip': '10.0.0.10',
                        'port': '8080',
                        'url': 'http://10.0.0.10:8080},
                    'svc2': {
                        'proto': 'https',
                        'ip': '10.0.0.20',
                        'port': '8443',
                        'url': 'https://10.0.0.20:8443},
                ...

        """
        info = {}
        proto = 'https' if self.apache_enabled else 'http'
        if self.port_map:
            for service in self.port_map.keys():
                key = service.replace('-', '_')
                info[key] = {
                    'proto': proto,
                    'ip': os_ip.resolve_address(os_ip.ADMIN),
                    'port': self.port_map[service][os_ip.ADMIN]}
                info[key]['url'] = '{proto}://{ip}:{port}'.format(**info[key])
        return info

    def get_network_addresses(self):
        """For each network configured, return corresponding address and vip
           (if available).

        Returns a list of tuples of the form:

            [(address_in_net_a, vip_in_net_a),
             (address_in_net_b, vip_in_net_b),
             ...]

            or, if no vip(s) available:

            [(address_in_net_a, address_in_net_a),
             (address_in_net_b, address_in_net_b),
             ...]
        """
        addresses = []
        for net_type in ADDRESS_TYPES:
            net_cfg_opt = os_ip.ADDRESS_MAP[net_type]['config'].replace('-',
                                                                        '_')
            config_cidr = getattr(self, net_cfg_opt, None)
            addr = ch_ip.get_address_in_network(
                config_cidr,
                hookenv.unit_get('private-address'))
            addresses.append(
                (addr, os_ip.resolve_address(endpoint_type=net_type)))
        return sorted(addresses)

    @property
    def endpoints(self):
        """List of endpoint information.

           Endpoint information used to configure apache
           Client -> endpoint -> address:ext_port -> local:int_port

           NOTE: endpoint map be a vi
           returns [
               (address1, endpoint1, ext_port1, int_port1),
               (address2, endpoint2, ext_port2, int_port2)
           ...
           ]
        """
        endpoints = []
        for address, endpoint in sorted(set(self.network_addresses)):
            for api_port in self.external_ports:
                ext_port = ch_cluster.determine_apache_port(
                    api_port,
                    singlenode_mode=True)
                int_port = ch_cluster.determine_api_port(
                    api_port,
                    singlenode_mode=True)
                portmap = (address, endpoint, int(ext_port), int(int_port))
                endpoints.append(portmap)
        return endpoints

    @property
    def ext_ports(self):
        """ List of endpoint ports

            @returns List of ports
        """
        eps = [ep[2] for ep in self.endpoints]
        return sorted(list(set(eps)))

    @property
    def use_memcache(self):
        return self.memcache.get('use_memcache', False)

    @property
    def memcache_server(self):
        return self.memcache.get('memcache_server', '')

    @property
    def memcache_host(self):
        return self.memcache.get('memcache_server_formatted', '')

    @property
    def memcache_port(self):
        return self.memcache.get('memcache_port', '')

    @property
    def memcache_url(self):
        return self.memcache.get('memcache_url', '')

    @property
    @hookenv.cached
    def memcache(self):
        ctxt = {}
        ctxt['use_memcache'] = False
        if self.charm_instance:
            if (ch_utils.OPENSTACK_RELEASES.index(
                    self.charm_instance.release) >=
                    ch_utils.OPENSTACK_RELEASES.index('mitaka')):
                ctxt['use_memcache'] = True

        if ctxt['use_memcache']:
            # Trusty version of memcached does not support ::1 as a listen
            # address so use host file entry instead
            release = ch_host.lsb_release()['DISTRIB_CODENAME'].lower()
            if ch_ip.is_ipv6_disabled():
                if ch_host.CompareHostReleases(release) > 'trusty':
                    ctxt['memcache_server'] = '127.0.0.1'
                else:
                    ctxt['memcache_server'] = 'localhost'
                ctxt['memcache_server_formatted'] = '127.0.0.1'
                ctxt['memcache_port'] = '11211'
                ctxt['memcache_url'] = '{}:{}'.format(
                    ctxt['memcache_server_formatted'],
                    ctxt['memcache_port'])
            else:
                if ch_host.CompareHostReleases(release) > 'trusty':
                    ctxt['memcache_server'] = '::1'
                else:
                    ctxt['memcache_server'] = 'ip6-localhost'
                ctxt['memcache_server_formatted'] = '[::1]'
                ctxt['memcache_port'] = '11211'
                ctxt['memcache_url'] = 'inet6:{}:{}'.format(
                    ctxt['memcache_server_formatted'],
                    ctxt['memcache_port'])
        return ctxt

    @property
    @hookenv.cached
    def workers(self):
        """Return the a number of workers that depends on the
        config('worker_muliplier') and the number of cpus.   This function uses
        the charmhelpers.contrib.openstack.context.WorkerConfigContext() to do
        the heavy lifting so that any changes in charmhelpers propagate to this
        function

        :returns: <int> the number of workers to apply to a configuration file.
        """
        return ch_context.WorkerConfigContext()()["workers"]

    @property
    @hookenv.cached
    def wsgi_worker_context(self):
        """Return a WSGIWorkerConfigContext dictionary.

        This is used to configure a WSGI worker.  The charm_instance class can
        define some attributes (or properties - anything getattr(...) will work
        against for:

            wsgi_script: a script/name to pass to the WSGIW... constructor
            wsgi_admin_script: a script/name to pass to the WSGIW...
                constructor
            wsgi_public_script: a script/name to pass to the WSGIW...
                constructor
            wsgi_process_weight: an float between 0.0 and 1.0 to split the
                share of all workers between main, admin and public workers.
            wsgi_admin_process_weight: an float between 0.0 and 1.0 to split
                the share of all workers between main, admin and public workers
            wsgi_public_process_weight: an float between 0.0 and 1.0 to split
                the share of all workers between main, admin and public workers

            The sum of the process weights should equal 1 to make sense.

        :returns: WSGIWorkerConfigContext dictionary.
        """
        charm_instance = self.charm_instance or {}
        kwargs = dict(
            name=getattr(charm_instance, 'name', None),
            script=getattr(charm_instance, 'wsgi_script', None),
            admin_script=getattr(charm_instance, 'wsgi_admin_script', None),
            public_script=getattr(charm_instance, 'wsgi_public_script', None),
            process_weight=getattr(
                charm_instance, 'wsgi_process_weight', None),
            admin_process_weight=getattr(
                charm_instance, 'wsgi_admin_process_weight', None),
            public_process_weight=getattr(
                charm_instance, 'wsgi_public_process_weight', None),
        )
        # filtering the kwargs of Nones allows the default arguments on
        # WSGIWorkerConfigContext.__init__(...) to be used.
        filtered_kwargs = dict((k, v) for k, v in kwargs.items()
                               if v is not None)
        return ch_context.WSGIWorkerConfigContext(**filtered_kwargs)()


def make_default_relation_adapter(base_cls, relation, properties):
    """Create a default relation adapter using a base class, and custom
    properties for various relations that may have been defined as custom
    properties.

    This mixes the declarative 'custom' properties + with the default classes
    to provide a class that manages the relation for the charm.

    This mixes the associated RelationAdapter class with the custom relations.

    :param base_cls: the class to use as the base for the properties
    :param relation: the relation we want the properties for
    :param properties: {key: function} functions to make custom properties
    """
    # Just return the base_cls if there's nothing to modify
    if not properties:
        return base_cls
    # convert the functions into properties
    props = {n: property(f) for n, f in properties.items()}
    # turn 'my-Something_interface' into 'MySomethingInterface'
    # future proof incase other chars come in which can't be in an Python Class
    # name.
    relation = re.sub(r'[^a-zA-Z_-]', '', relation)
    parts = relation.replace('-', '_').lower().split('_')
    header = ''.join([s.capitalize() for s in parts])
    name = "{}RelationAdapterModified".format(header)
    # and make the class
    return type(name, (base_cls,), props)


class OpenStackRelationAdapters(object):
    """
    Base adapters class for OpenStack Charms, used to aggregate
    the relations associated with a particular charm so that their
    properties can be accessed using dot notation, e.g:

        adapters.amqp.private_address
    """

    relation_adapters = {}
    """
    Dictionary mapping relation names to adapter classes, e.g:

        relation_adapters = {
            'amqp': RabbitMQRelationAdapter,
        }

    By default, relations will be wrapped in an OpenStackRelationAdapter.

    Each derived class can define their OWN relation_adapters and they will
    overlay on the class further back in the class hierarchy, according to the
    mro() for the class.
    """

    def __init__(self, relations, options=None, options_instance=None,
                 charm_instance=None):
        """
        :param relations: List of instances of relation classes
        :param options: Configuration class to use (DEPRECATED)
        :param options_instance: Instance of Configuration class to use
        :param charm_instance: optional charm_instance that is captured as a
            weakref for use on the adapter.
        """
        self._charm_instance_weakref = None
        if charm_instance is not None:
            self._charm_instance_weakref = weakref.ref(charm_instance)
        self._relations = set()
        if options is not None:
            hookenv.log("The 'options' argument is deprecated please use "
                        "options_instance instead.", level=hookenv.WARNING)
            self.options = options()
        elif options_instance is not None:
            self.options = options_instance
        else:
            # create a default, customised ConfigurationAdapter if the
            # APIConfigurationAdapter is needed as a base, then it must be
            # passed as an instance on the options_instance First pull the
            # configuration class from the charm instance (if it's available).
            base_cls = None
            if self.charm_instance:
                base_cls = getattr(self.charm_instance, 'configuration_class',
                                   base_cls)
            self.options = make_default_options(base_cls, self.charm_instance)
        self._relations.add('options')
        # walk the mro() from object to this class to build up the _adapters
        # ensure that all of the relations' have their '-' turned into a '_' to
        # ensure that everything is consistent in the class.
        self._adapters = {}
        for cls in reversed(self.__class__.mro()):
            self._adapters.update(
                {k.replace('-', '_'): v
                 for k, v in getattr(cls, 'relation_adapters', {}).items()})
        # now we have to add in any customisations to those adapters
        for relation, properties in _custom_adapter_properties.items():
            relation = relation.replace('-', '_')
            try:
                cls = self._adapters[relation]
            except KeyError:
                cls = OpenStackRelationAdapter
            self._adapters[relation] = make_default_relation_adapter(
                cls, relation, properties)
        self.add_relations(relations)

    @property
    def charm_instance(self):
        """Return the reference to the charm_instance or return None"""
        if self._charm_instance_weakref:
            return self._charm_instance_weakref()
        return None

    def __iter__(self):
        """
        Iterate over the relations presented to the charm.
        """
        for relation in self._relations:
            yield relation, getattr(self, relation)

    def add_relations(self, relations):
        """Add the relations to this adapters instance for use as a context.

        :params relations: list of RAW reactive relation instances.
        """
        for relation in relations:
            self.add_relation(relation)

    def add_relation(self, relation):
        """Add the relation to this adapters instance for use as a context.

        :param relation: a RAW reactive relation instance
        """
        adapter_name, adapter = self.make_adapter(relation)
        setattr(self, adapter_name, adapter)
        self._relations.add(adapter_name)

    def make_adapter(self, relation):
        """Make an adapter from a reactive relation.
        This returns the relation_name and the adapter instance based on the
        registered custom adapter classes and any customised properties on
        those adapter classes.

        :param relation: a RelationBase derived reactive relation
        :returns (string, OpenstackRelationAdapter-derived): see above.
        """
        relation_name = relation.relation_name.replace('-', '_')
        try:
            adapter = self._adapters[relation_name](relation)
        except KeyError:
            adapter = OpenStackRelationAdapter(relation)
        return relation_name, adapter


class OpenStackAPIRelationAdapters(OpenStackRelationAdapters):

    relation_adapters = {
        'amqp': RabbitMQRelationAdapter,
        'shared_db': DatabaseRelationAdapter,
        'cluster': PeerHARelationAdapter,
    }

    def __init__(self, relations, options=None, options_instance=None,
                 charm_instance=None):
        """
        :param relations: List of instances of relation classes
        :param options: Configuration class to use (DEPRECATED)
        :param options_instance: Instance of Configuration class to use
        :param charm_instance: an instance of the charm class
        """
        super(OpenStackAPIRelationAdapters, self).__init__(
            relations,
            options=options,
            options_instance=options_instance,
            charm_instance=charm_instance)
        if 'cluster' not in self._relations:
            # cluster has not been passed through already, so try to resolve it
            # automatically when it is accessed.
            self.__resolved_cluster = None
            # add a property for the cluster to resolve it
            self._relations.add('cluster')
            setattr(self.__class__, 'cluster',
                    property(lambda x: x.__cluster()))

    def __cluster(self):
        """The cluster relations is auto added onto adapters instance"""
        if not self.__resolved_cluster:
            self.__resolved_cluster = self.__resolve_cluster()
        return self.__resolved_cluster

    def __resolve_cluster(self):
        """ Resolve what the cluster adapter is.

        LY: The cluster interface only gets initialised if there are more
        than one unit in a cluster, however, a cluster of one unit is valid
        for the Openstack API charms. So, create and populate the 'cluster'
        namespace with data for a single unit if there are no peers.

        :returns: cluster adapter or None
        """
        smm = PeerHARelationAdapter(relation_name='cluster').single_mode_map
        if smm:
            return smm
        else:
            # LY: Automatically add the cluster relation if it exists and
            # has not been passed through.
            cluster_rel = reactive.RelationBase.from_state('cluster.connected')
            if cluster_rel:
                return PeerHARelationAdapter(relation=cluster_rel)
        return None
