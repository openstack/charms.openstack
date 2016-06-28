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

# need/want absolute imports for the package imports to work properly
from __future__ import absolute_import
import netaddr

import charmhelpers.core.hookenv as hookenv
import charmhelpers.contrib.network.ip as net_ip
import charmhelpers.contrib.hahelpers.cluster as cluster
import charms.reactive.bus

PUBLIC = 'public'
INTERNAL = 'int'
ADMIN = 'admin'

ADDRESS_MAP = {
    PUBLIC: {
        'binding': 'public',
        'config': 'os-public-network',
        'fallback': 'public-address',
        'override': 'os-public-hostname',
    },
    INTERNAL: {
        'binding': 'internal',
        'config': 'os-internal-network',
        'fallback': 'private-address',
        'override': 'os-internal-hostname',
    },
    ADMIN: {
        'binding': 'admin',
        'config': 'os-admin-network',
        'fallback': 'private-address',
        'override': 'os-admin-hostname',
    },
}


def canonical_url(endpoint_type=PUBLIC):
    """
    Returns the correct HTTP URL to this host given the state of HTTPS
    configuration, hacluster and charm configuration.

    :param endpoint_type str: The endpoint type to resolve.

    :returns str: Base URL for services on the current service unit.
    """
    scheme = 'http'
    if charms.reactive.bus.get_state('ssl.enabled'):
        scheme = 'https'
    address = resolve_address(endpoint_type)
    if net_ip.is_ipv6(address):
        address = "[{}]".format(address)
    return "{0}://{1}".format(scheme, address)


def _get_address_override(endpoint_type=PUBLIC):
    """Returns any address overrides that the user has defined based on the
    endpoint type.

    Note: this function allows for the service name to be inserted into the
    address if the user specifies {service_name}.somehost.org.

    :param endpoint_type: the type of endpoint to retrieve the override
                          value for.
    :returns: any endpoint address or hostname that the user has overridden
              or None if an override is not present.
    """
    override_key = ADDRESS_MAP[endpoint_type]['override']
    addr_override = hookenv.config(override_key)
    if not addr_override:
        return None
    else:
        return addr_override.format(service_name=hookenv.service_name())


def _network_get_primary_address(binding):
    """Wrapper for hookenv.network_get_primary_address

    hookenv.network_get_primary_address may return a string or bytes depending
    on the version of python (Bug #1595418). When fix has landed in pypi
    wrapper may be discarded"""
    try:
        address = hookenv.network_get_primary_address(binding).decode('utf-8')
    except AttributeError:
        address = hookenv.network_get_primary_address(binding)
    return address


def _resolve_network_cidr(ip_address):
    '''
    Resolves the full address cidr of an ip_address based on
    configured network interfaces

    This is in charmhelpers trunk but not in pypi. Please revert to using
    charmhelpers version when pypi has been updated
    '''
    netmask = net_ip.get_netmask_for_address(ip_address)
    return str(netaddr.IPNetwork("%s/%s" % (ip_address, netmask)).cidr)


def resolve_address(endpoint_type=PUBLIC, override=True):
    """Return unit address depending on net config.

    If unit is clustered with vip(s) and has net splits defined, return vip on
    correct network. If clustered with no nets defined, return primary vip.

    If not clustered, return unit address ensuring address is on configured net
    split if one is configured, or a Juju 2.0 extra-binding has been used.

    :param endpoint_type: Network endpoing type
    :param override: Accept hostname overrides or not
    """
    resolved_address = None
    if override:
        resolved_address = _get_address_override(endpoint_type)
        if resolved_address:
            return resolved_address

    vips = hookenv.config('vip')
    if vips:
        vips = vips.split()

    net_type = ADDRESS_MAP[endpoint_type]['config']
    net_addr = hookenv.config(net_type)
    net_fallback = ADDRESS_MAP[endpoint_type]['fallback']
    binding = ADDRESS_MAP[endpoint_type]['binding']
    clustered = cluster.is_clustered()

    if clustered and vips:
        if net_addr:
            for vip in vips:
                if net_ip.is_address_in_network(net_addr, vip):
                    resolved_address = vip
                    break
        else:
            # NOTE: endeavour to check vips against network space
            #       bindings
            try:
                bound_cidr = _resolve_network_cidr(
                    _network_get_primary_address(binding)
                )
                for vip in vips:
                    if net_ip.is_address_in_network(bound_cidr, vip):
                        resolved_address = vip
                        break
            except NotImplementedError:
                # If no net-splits configured and no support for extra
                # bindings/network spaces so we expect a single vip
                resolved_address = vips[0]
    else:
        if hookenv.config('prefer-ipv6'):
            fallback_addr = net_ip.get_ipv6_addr(exc_list=vips)[0]
        else:
            fallback_addr = hookenv.unit_get(net_fallback)

        if net_addr:
            resolved_address = net_ip.get_address_in_network(net_addr,
                                                             fallback_addr)
        else:
            # NOTE: only try to use extra bindings if legacy network
            #       configuration is not in use
            try:
                resolved_address = _network_get_primary_address(binding)
            except NotImplementedError:
                resolved_address = fallback_addr

    if resolved_address is None:
        raise ValueError("Unable to resolve a suitable IP address based on "
                         "charm state and configuration. (net_type=%s, "
                         "clustered=%s)" % (net_type, clustered))

    return resolved_address
