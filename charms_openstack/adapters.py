"""Adapter classes and utilities for use with Reactive interfaces"""
from __future__ import absolute_import

import charms.reactive.bus
import charmhelpers.contrib.hahelpers.cluster as ch_cluster
import charmhelpers.contrib.network.ip as ch_ip
import charmhelpers.contrib.openstack.utils as ch_utils
import charmhelpers.core.hookenv

ADDRESS_TYPES = ['admin', 'internal', 'public']


class OpenStackRelationAdapter(object):
    """
    Base adapter class for all OpenStack related adapters.
    """

    interface_type = None
    """
    The generic type of the interface the adapter is wrapping.
    """

    def __init__(self, relation, accessors=None):
        self.relation = relation
        self.accessors = accessors or []
        self._setup_properties()

    @property
    def relation_name(self):
        """
        Name of the relation this adapter is handling.
        """
        return self.relation.relation_name

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


class PeerHARelationAdapter(OpenStackRelationAdapter):
    """
    Adapter for cluster relation of nodes of the same service
    """

    interface_type = "cluster"

    def __init__(self, relation):
        super(PeerHARelationAdapter, self).__init__(relation)
        self.config = charmhelpers.core.hookenv.config()
        self.local_address = APIConfigurationAdapter().local_address
        self.local_unit_name = APIConfigurationAdapter().local_unit_name
        self.cluster_hosts = {}
        self.add_network_split_addresses()
        self.add_default_addresses()

    @staticmethod
    def local_network_split_addresses():
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
        config = charmhelpers.core.hookenv.config()
        local_unit_name = APIConfigurationAdapter().local_unit_name
        _cluster_hosts = {}
        for addr_type in ADDRESS_TYPES:
            cfg_opt = 'os-{}-network'.format(addr_type)
            laddr = ch_ip.get_address_in_network(config.get(cfg_opt))
            if laddr:
                netmask = ch_ip.get_netmask_for_address(laddr)
                _cluster_hosts[laddr] = {
                    'network': "{}/{}".format(laddr, netmask),
                    'backends': {local_unit_name: laddr}}
        return _cluster_hosts

    @staticmethod
    def local_default_addresses():
        """Map of local units private address

           @return dict of private address info local unit e.g.
               {'this_unit_private_addr': {
                    'backends': {
                        'this_unit-1': 'this_unit_private_addr'},
                    'network': 'this_unit_private_addr/private_netmask'}}

        """
        local_unit_name = APIConfigurationAdapter().local_unit_name
        local_address = APIConfigurationAdapter().local_address
        netmask = ch_ip.get_netmask_for_address(local_address)
        _local_map = {
            local_address: {
                'network': "{}/{}".format(local_address, netmask),
                'backends': {local_unit_name: local_address}}}
        return _local_map

    def add_network_split_addresses(self):
        """Populate cluster_hosts with addresses of this unit and its
           peers on each address type

           @return None
        """
        local_addresses = PeerHARelationAdapter.local_network_split_addresses()
        for addr_type in ADDRESS_TYPES:
            cfg_opt = 'os-{}-network'.format(addr_type)
            laddr = ch_ip.get_address_in_network(self.config.get(cfg_opt))
            if laddr:
                self.cluster_hosts[laddr] = local_addresses[laddr]
                key = '{}-address'.format(addr_type)
                for _unit, _laddr in self.relation.ip_map(address_key=key):
                    self.cluster_hosts[laddr]['backends'][_unit] = _laddr

    def add_default_addresses(self):
        """Populate cluster_hosts with private-address of this unit and its
           peers

           @return None
        """
        self.cluster_hosts[self.local_address] = \
            PeerHARelationAdapter.local_default_addresses()[self.local_address]
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
        Hostname that should be used to access RabbitMQ.
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


class ConfigurationAdapter(object):
    """
    Configuration Adapter which provides python based access
    to all configuration options for the current charm.
    """

    def __init__(self):
        _config = charmhelpers.core.hookenv.config()
        for k, v in _config.items():
            k = k.replace('-', '_')
            setattr(self, k, v)


class APIConfigurationAdapter(ConfigurationAdapter):
    """This configuration adapter extends the base class and adds properties
    common accross most OpenstackAPI services"""

    def __init__(self, port_map=None):
        super(APIConfigurationAdapter, self).__init__()
        self.port_map = port_map
        self.config = charmhelpers.core.hookenv.config()

    @property
    def ipv6_mode(self):
        """Return if charm should enable IPv6

        @return True if user has requested ipv6 support otherwise False
        """
        return self.config.get('prefer-ipv6', False)

    @property
    def local_address(self):
        """Return remotely accessible address of charm (not localhost)

        @return True if user has requested ipv6 support otherwise False
        """
        if self.ipv6_mode:
            addr = ch_ip.get_ipv6_addr(exc_list=[self.config.get('vip')])[0]
        else:
            addr = ch_utils.get_host_ip(
                charmhelpers.core.hookenv.unit_get('private-address'))
        return addr

    @property
    def local_unit_name(self):
        """
        @return local unit name
        """
        return charmhelpers.core.hookenv.local_unit().replace('/', '-')

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
        service_ports = {}
        if self.port_map:
            for service in self.port_map.keys():
                service_ports[service] = [
                    self.port_map[service]['admin'],
                    ch_cluster.determine_apache_port(
                        self.port_map[service]['admin'],
                        singlenode_mode=True)]
        return service_ports

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
        if self.port_map:
            for service in self.port_map.keys():
                key = service.replace('-', '_')
                info[key] = {
                    'proto': 'http',
                    'ip': self.local_address,
                    'port': ch_cluster.determine_apache_port(
                        self.port_map[service]['admin'],
                        singlenode_mode=True)}
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
        ip = self.config.get('vip', self.local_address)
        if self.port_map:
            for service in self.port_map.keys():
                key = service.replace('-', '_')
                info[key] = {
                    'proto': 'http',
                    'ip': ip,
                    'port': self.port_map[service]['admin']}
                info[key]['url'] = '{proto}://{ip}:{port}'.format(**info[key])
        return info


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
    """

    _adapters = {
        'amqp': RabbitMQRelationAdapter,
        'shared_db': DatabaseRelationAdapter,
        'cluster': PeerHARelationAdapter,
    }
    """
    Default adapter mappings; may be overridden by relation adapters
    in subclasses.

    Additional kwargs can be passed to the configuration adapterwhich has been
    specified via the options parameter
    """

    def __init__(self, relations, options=ConfigurationAdapter, **kwargs):
        self._adapters.update(self.relation_adapters)
        self._relations = []
        cluster_relid = charmhelpers.core.hookenv.relation_ids('cluster')[0]
        if not charmhelpers.core.hookenv.related_units(relid=cluster_relid):
            relation_value = {
                'cluster_hosts':
                    PeerHARelationAdapter.local_default_addresses(),
            }
            setattr(self, 'cluster', relation_value)
            self._relations.append('cluster')
        for relation in relations:
            relation_name = relation.relation_name.replace('-', '_')
            try:
                relation_value = self._adapters[relation_name](relation)
            except KeyError:
                relation_value = OpenStackRelationAdapter(relation)
            setattr(self, relation_name, relation_value)
            self._relations.append(relation_name)
        self.options = options(**kwargs)
        self._relations.append('options')

    def __iter__(self):
        """
        Iterate over the relations presented to the charm.
        """
        for relation in self._relations:
            yield relation, getattr(self, relation)
