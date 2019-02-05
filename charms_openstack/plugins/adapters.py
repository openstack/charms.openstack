# Copyright 2019 Canonical Ltd
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

import charms_openstack.adapters


class CephRelationAdapter(charms_openstack.adapters.OpenStackRelationAdapter):
    """
    Adapter class for Ceph interfaces.
    """

    # NOTE(fnordahl): the ``interface_type`` variable holds informational value
    # only.  This relation adapter can be used with any interface that
    # provides the properties or functions referenced in this class.
    interface_type = "ceph-mon"

    @property
    def monitors(self):
        """
        Provide comma separated list of hosts that should be used
        to access Ceph.

        The mon_hosts function in Ceph interfaces tend to return a list or
        generator object.

        We need a comma separated string for use in our configuration
        templates.

        The sorting is important to avoid service restarts just because
        of entries changing order in the returned data.

        NOTE(fnordahl): Adapted from jamesapage's adapter in ``charm-gnocchi``

        :returns: comma separated string with Ceph monitor hosts
        :rtype: str
        """
        hosts = sorted(self.relation.mon_hosts())

        if len(hosts) > 0:
            return ','.join(hosts)
        else:
            return ''
