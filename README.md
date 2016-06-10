# charms.openstack [![Build Status](https://travis-ci.org/openstack-charmers/charms.openstack.svg?branch=master)](https://travis-ci.org/openstack-charmers/charms.openstack)

Helpers for building layered, reactive OpenStack charms.

# Support and discussions

We use the openstack-charmers mailing-lists for developer and user discussions, you can
find and subscribe here: https://lists.ubuntu.com/openstack-charmers.

If you prefer live discussions, some of us also hang out in
[#juju](http://webchat.freenode.net/?channels=#juju) on irc.freenode.net.

# Bug reports

Bug reports can be filed at https://bugs.launchpad.net/charms.openstack/+filebug

# Using `charms.openstack`

charms.openstack provides a module `charms_openstack` which is included in
layer-openstack's `wheelhouse.txt`. It is provides the fundamental
functionality required of _most_ OpenStack charms.

The main classes that the module provides are:

 * :class:`OpenStackRelationAdapter`
 * :class:`RabbitMQRelationAdapter`
 * :class:`DatabaseRelationAdapter`
 * :class:`ConfigurationAdapter`
 * :class:`OpenStackRelationsAdapter`
 * :class:`OpenStackCharm`

# Key features of `charms.openstack`

The main features that `charms.openstack` provides are:

 * a base `OpenStackCharm` that provides:
   * The ability to specify the OpenStack release that the charm works with.
   * The list of packages to install on the charm.
   * The ports that the charm exposes.
   * The keystone service type (if applicable)
   * A mapping of config files to services to restart if the configuration
     changes.
   * The required relations for the charm (workload status)
   * The sync command that the database (if associated) will need for its
     schema.
   * a default install that gets the packages, installs them, and sets the
     appropriate workload status.
   * A configuration file renderer (using the relation adapters) to write
     the configuration files for the service being managed.
   * A workload status helper (`assess_status()`) that checks the state of
     interfaces, the services, and ports, and sets the workload status. This
     is automatically provided for the `update-status` hook in the `layer-openstack`
     layer.

# How to leverage `charms.openstack` classes

## Using `OpenStackCharm`

`OpenStackCharm()` and the related classes provide a powerful framework to
build an OpenStack charm on.  There are two approaches to writing charms that
support multiple OpenStack releases.  Note that determining the release _is up
to the charm author_, and can be signalled to `OpenStackCharm` in two ways.

 1. Write a single `OpenStackCharm` derived class that uses `self.release` to
    determine what functionality to exhibit depending on the release. In this
    case, there is no need to register multiple charms and provide a _chooser_
    to determine which class to use.

 2. Write muliple `OpenStackCharm` derived classes which map to each difference
    in charm functionality depending on the release, and register a _chooser_
    function using the `@register_os_release_selector` decorator.

e.g.

```python
class LibertyCharm(OpenStackCharm):
    release = 'liberty'

class MitakaCharm(OpenStackCharm):
    release = 'mitaka'

@register_os_release_selector
def choose_release():
    """Determine the release based on the python-keystonemiddleware that is
    installed.
    """
    return ch_utils.os_release('python-keystonemiddleware')
```

This will automatically select `LibertyCharm` for a liberty release and
`MitakaCharm` for the mitaka release.  Note, that it will also _set_ `release`
on the `OpenStackCharm` instance via the `__init__()` method, so that the
instance knows what the charm is.

If only a single charm class is needed, the the `__init__()` method of the
class can be used to determine the release instead:

```python
class TheCharm(OpenStackCharm):
    release = 'liberty'

    def __init__(release=None, *args, **kwargs):
        if release is None:
            release = ch_utils.os_release('python-keystonemiddleware')
        super(TheCharm, self).__init__(release=release, *args, **kwargs)
```

If the release selector function is registered, then the overridden
`__init__()` method is not needed as the release will be passed into the
default `__init__()` method.  However, there may be other functionality that
the charm author needs to include in the initialiser.

Note that using `os_release()` can typically be used to determine the release
of OpenStack.

## Using the relation adapter classes - OpenStackRelationAdapter

The relation adapter classes adapt a reactive interface for use in the
rendering functions.  Their pricipal use is to provide an iterator of the
attributes declared in the `assessors` attribute of the instance.

A reactive `BaseRelation` derived instance has an `auto_accessors` attribute
which declares the variables that the relation has.  These are copied into the
`accessors` attribute of the `OpenStackRelationAdapter` class, and additional
attributes can be added as part of class instantiation.

Note that the `accessor` properties are _dynamic_, in that they call the
underlying relation property when they are accessed.

The _purpose_ of the `OpenStackRelation` class is for the instance to be used
as part of configuration file rendering, as an instance of an
`OpenStackRelation` class can be passed to the render function, and the
iterator will provide the _key value_ pairs to the template processor.

A derived `OpenStackRelation` class can provide additional _computed_
properties as required. e.g. the `RabbitMQRelationAdapter` implementation:

```python
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
```

Note that the additional accessors `vhost` and `username` are provided in the
overridden `__init__()` method.

## The `ConfigurationAdapter`

The `ConfigurationAdapter` class simply provides _snapshot_ of the
configuration opentions for the current charm, such that they can be accessed
as attributes of an instance of the class.  e.g. rather than `config('vip')`
then user can use `c_adapter.vip`.

The benefit, is that a _derived_ version of `ConfigurationAdapter` can be
provided that has _computed_ properties that can be used like static properties
on the instance.  The `ConfigurationAdapter`, or derived class, is used with
the `OpenStackRelationAdapters` class (not the plural _...Adapters_) class that
brings together all of the relations into one place.

## The `OpenStackRelationAdapters` class

The `OpenStackRelationAdapters` class joins together the relation adapter
classes, with the `ConfigurationAdapter` (or derived) class, and works _like_
a charmhelpers `OSRenderConfig` instance to the rendering functions in
charmhelpers.

Thus an instance of the `OpenStackRelationAdapters` (or derived) class is used
in  the `charmhelpers.core.templating.render()` function to provide the
variables needed to render templates.

The `OpenStackRelationAdapters` class can be subclassed (derived) with
additional custom `OpenStackRelationAdapter` classes (to map to particular
relations) using the `relation_adapters` class property:

```python
class MyRelationAdapters(OpenStackRelationAdapters):

    relation_adapters = {
       'my-relation': MyRelationAdapter,
    }
```

This enables custome relation adapters to be mapped to particular relations
such that custom functionality can be implemented for a particular reactive
relationship.

## HighAvailability Support

To be completed.

## Workload status

OpenStack charms support the concept of _workload status_ which helps to inform
a user of the charm of the current state of the charm.  The following workload
statuses are supported:

 * unknown - The charm _doesn't_ support workload status.  This should **not**
   be used for charms that DO support workload status.
 * active - The unit under the charms control is fully configuration
   and available for use.
 * maintenance - the unit is installing, or doing something of that nature.
 * waiting - The unit is waiting for a relation to become available. i.e. the
   relation is not yet _complete_ in that some data is missing still.
 * blocked - a relation is not yet connected, or some other blocking
   condition.
 * paused - (Not yet availble) - the unit has been put into the paused state.

The default is for charms to support workload status, and the default installation method sets the status to maintenance with an install message.

If the charm is not going to support workload status, _and this is not
recommended_, then the charm author will need to override the `install()`
method of `OpenStackCharm` derived class to disable setting the `maintenance`
state, and override the `assess_status()` method to a NOP.

The `assess_status()` method on `OpenStackCharm` provides a helper to enable
the charm author to provide workload status.  By default:

 * The install method provides the maintenance status.
 * The `layer-openstack` layer provides a hook for `update-status` which
   calls the `assess_status()` function on the charm class.
 * The `assess_status()` method uses various attributes of the class to provide
   a default mechanism for assessing the workload status of the charm/unit.

The latter is extremely useful for determining the workload status. The
`assess_status()` method does the following checks:

 1. The unit checks if it is paused. (Not yet available as a feature).
 2. The unit checks the relations to see if they are connected and available.
 3. The unit checks `custom_assess_status_check()`
 4. The unit checks that the services are running and ports are open.

### Checking of relations

The assess_status function checks that the relations named in the class
attribute `required_relations` are connected and available.  It does this using
the convention of:

 * A connected relation has the `{relation}.connected` state set.
 * An available relation has the `{relation}.available` state set.

This is a convention that the interfaces (e.g. interface-keystone, etc.) use.
interface-keystone sets `identity-service.connected` when it has a connection
with keystone, and `identity-service.available` when the connection is
completed and all information transferred.

That if `required_relations` is `['identity-service']`, then the
`assess_status()` function will check for `identity-service.connected` and
`identity-service.available` states.

If the charm author requires additional states to be checked for an interface,
then the  method `states_to_check` should be overriden in the derived class and
additional states, the status and error message provided.  See the code for
further details.

e.g.

```python
def states_to_check():
    states = super(MyCharm, self).states_to_check()
    states['some-relation'].append(
        ("some-relation.available.ssl", "waiting", "'some-relation' incomplete"))
    return states
```

### The `custom_assess_status_check()` method

If the charm author needs to do additional status checking, then the
`custom_assess_status_check()` method should be overridden in the derived
class. The return value from the method is:

 * (None, None) - the unit is fine.
 * status, message - the unit's workload status is not active.

### Not checking services are running

By default, the `assess_status()` method checks that the services declared in
the class attribute `services` (list of strings) are checked to ensure that
they are running.  Additionally, the ports declared in the class attribute
`api_ports` are also checked for being _listened on_.

However, if the services check is not required, then the derived class should
overload the `check_running_services()` method and return `None, None`.

Additionally, if the services running check _is_ required, but the ports should
not be checked, then the `ports_to_check` method can be overridden and return
an empty list `[]`.

### Using `assess_status()`

The `assess_status()` method should be used on any hook or state method where
the unit's status may have changed.  e.g. interfaces connecting or becoming
available, configuration changes, etc.

e.g.

```python
@reactive.when('amqp.connected')¬
def setup_amqp_req(amqp):¬
    """Use the amqp interface to request access to the amqp broker using our
    local configuration.
    """
    amqp.request_access(username=hookenv.config('rabbit-user'),
                        vhost=hookenv.config('rabbit-vhost'))
    MyCharm.singleton.assess_status()
```
