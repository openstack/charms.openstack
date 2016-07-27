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

import charms.reactive.bus
import charmhelpers.contrib.hahelpers.cluster as ch_cluster
import charmhelpers.contrib.network.ip as ch_ip
import charmhelpers.contrib.openstack.utils as ch_utils
import charmhelpers.core.hookenv as hookenv
import charms_openstack.ip as os_ip

ADDRESS_TYPES = os_ip.ADDRESS_MAP.keys()


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
        self.cluster_hosts = {}
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
        return sorted(list(self.cluster_hosts[laddr]['backends'].values()))

    @property
    def single_mode_map(self):
        """Return map of local addresses only if this is a single node cluster

           @return dict of private address info local unit e.g.
               {'cluster_hosts':
                   {'this_unit_private_addr': {
                        'backends': {
                            'this_unit-1': 'this_unit_private_addr'},
                        'network': 'this_unit_private_addr/private_netmask'}}
        """
        relation_info = {}
        try:
            cluster_relid = hookenv.relation_ids('cluster')[0]
            if not hookenv.related_units(relid=cluster_relid):
                relation_info = {
                    'cluster_hosts': self.local_default_addresses(),
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
                    'backends': {self.local_unit_name: laddr}}
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
                'backends': {self.local_unit_name: self.local_address}}}
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
        _config = hookenv.config()
        for k, v in _config.items():
            k = k.replace('-', '_')
            setattr(self, k, v)


class APIConfigurationAdapter(ConfigurationAdapter):
    """This configuration adapter extends the base class and adds properties
    common accross most OpenstackAPI services"""

    def __init__(self, port_map=None, service_name=None):
        """
        :param  port_map: Map containing service names and the ports used e.g.
                port_map = {
                        'svc1': {
                        'admin': 9001,
                        'public': 9001,
                        'internal': 9001,
                    },
                        'svc2': {
                        'admin': 9002,
                        'public': 9002,
                        'internal': 9002,
                    },
                }
        :param service_name: Name of service being deployed
        """
        super(APIConfigurationAdapter, self).__init__()
        self.port_map = port_map
        self.service_name = service_name
        self.network_addresses = self.get_network_addresses()

    @property
    def external_ports(self):
        """Return ports the service will be accessed on

        @return set of ports service can be accessed on
        """
        ext_ports = set()
        for svc in self.port_map.keys():
            for net_type in self.port_map[svc].keys():
                ext_ports.add(self.port_map[svc][net_type])
        return ext_ports

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
        service_ports = {}
        if self.port_map:
            for service in self.port_map.keys():
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
        ip = getattr(self, 'vip', self.local_address)
        proto = 'https' if self.apache_enabled else 'http'
        if self.port_map:
            for service in self.port_map.keys():
                key = service.replace('-', '_')
                info[key] = {
                    'proto': proto,
                    'ip': ip,
                    'port': self.port_map[service]['admin']}
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

    _adapters = {}
    """
    Default adapter mappings; may be overridden by relation adapters
    in subclasses.
    """

    def __init__(self, relations, options=None, options_instance=None):
        """
        :param relations: List of instances of relation classes
        :param options: Configuration class to use (DEPRECATED)
        :param options_instance: Instance of Configuration class to use
        """
        self._relations = []
        if options:
            hookenv.log("The 'options' argument is deprecated please use "
                        "options_instance instead.", level=hookenv.WARNING)
            self.options = options()
        else:
            self.options = options_instance or ConfigurationAdapter()
        self._relations.append('options')
        self._adapters.update(self.relation_adapters)
        for relation in relations:
            relation_name = relation.relation_name.replace('-', '_')
            try:
                relation_value = self._adapters[relation_name](relation)
            except KeyError:
                relation_value = OpenStackRelationAdapter(relation)
            setattr(self, relation_name, relation_value)
            self._relations.append(relation_name)

    def __iter__(self):
        """
        Iterate over the relations presented to the charm.
        """
        for relation in self._relations:
            yield relation, getattr(self, relation)


class OpenStackAPIRelationAdapters(OpenStackRelationAdapters):

    _adapters = {
        'amqp': RabbitMQRelationAdapter,
        'shared_db': DatabaseRelationAdapter,
        'cluster': PeerHARelationAdapter,
    }

    def __init__(self, relations, options=None, options_instance=None):
        """
        :param relations: List of instances of relation classes
        :param options: Configuration class to use (DEPRECATED)
        :param options_instance: Instance of Configuration class to use
        """
        super(OpenStackAPIRelationAdapters, self).__init__(
            relations,
            options=options,
            options_instance=options_instance)
        # LY: The cluster interface only gets initialised if there are more
        # than one unit in a cluster, however, a cluster of one unit is valid
        # for the Openstack API charms. So, create and populate the 'cluster'
        # namespace with data for a single unit if there are no peers.
        smm = PeerHARelationAdapter(relation_name='cluster').single_mode_map
        if smm:
            setattr(self, 'cluster', smm)
            self._relations.append('cluster')
