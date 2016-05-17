# need/want absolute imports for the package imports to work properly
from __future__ import absolute_import

import charmhelpers.core.hookenv as hookenv
import charmhelpers.contrib.network.ip as net_ip
import charmhelpers.contrib.hahelpers.cluster

PUBLIC = 'public'
INTERNAL = 'int'
ADMIN = 'admin'

_ADDRESS_MAP = {
    PUBLIC: {
        'config': 'os-public-network',
        'fallback': 'public-address'
    },
    INTERNAL: {
        'config': 'os-internal-network',
        'fallback': 'private-address'
    },
    ADMIN: {
        'config': 'os-admin-network',
        'fallback': 'private-address'
    }
}


def canonical_url(endpoint_type=PUBLIC):
    """
    Returns the correct HTTP URL to this host given the state of HTTPS
    configuration, hacluster and charm configuration.

    :param endpoint_type str: The endpoint type to resolve.

    :returns str: Base URL for services on the current service unit.
    """
    scheme = 'http'
#    if 'https' in configs.complete_contexts():
#        scheme = 'https'
    address = resolve_address(endpoint_type)
    if net_ip.is_ipv6(address):
        address = "[{}]".format(address)
    return "{0}://{1}".format(scheme, address)


def resolve_address(endpoint_type=PUBLIC):
    """Return the address from the config() using endpoint_type to determine
    which address to return.

    It returns either the vip if the unit is clustered and there is no specific
    config() item for the specified address type.

    If the unit is not clustered then it attempts to return either the ipv6 or
    ipv4 address for the unit.
    """
    resolved_address = None
    if charmhelpers.contrib.hahelpers.cluster.is_clustered():
        if hookenv.config(_ADDRESS_MAP[endpoint_type]['config']) is None:
            # Assume vip is simple and pass back directly
            resolved_address = hookenv.config('vip')
        else:
            for vip in hookenv.config('vip').split():
                if net_ip.is_address_in_network(
                        hookenv.config(_ADDRESS_MAP[endpoint_type]['config']),
                        vip):
                    resolved_address = vip
    else:
        if hookenv.config('prefer-ipv6'):
            fallback_addr = net_ip.get_ipv6_addr(
                exc_list=[hookenv.config('vip')])[0]
        else:
            fallback_addr = hookenv.unit_get(
                _ADDRESS_MAP[endpoint_type]['fallback'])
        resolved_address = net_ip.get_address_in_network(
            hookenv.config(_ADDRESS_MAP[endpoint_type]['config']),
            fallback_addr)

    if resolved_address is None:
        raise ValueError('Unable to resolve a suitable IP address'
                         ' based on charm state and configuration')
    else:
        return resolved_address
