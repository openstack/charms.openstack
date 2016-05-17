"""Adapter classes and utilities for use with Reactive interfaces"""
from __future__ import absolute_import

import charmhelpers.core.hookenv


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
    }
    """
    Default adapter mappings; may be overridden by relation adapters
    in subclasses.
    """

    def __init__(self, relations, options=ConfigurationAdapter):
        self._adapters.update(self.relation_adapters)
        self._relations = []
        for relation in relations:
            relation_name = relation.relation_name.replace('-', '_')
            try:
                relation_value = self._adapters[relation_name](relation)
            except KeyError:
                relation_value = OpenStackRelationAdapter(relation)
            setattr(self, relation_name, relation_value)
            self._relations.append(relation_name)
        self.options = options()
        self._relations.append('options')

    def __iter__(self):
        """
        Iterate over the relations presented to the charm.
        """
        for relation in self._relations:
            yield relation, getattr(self, relation)
