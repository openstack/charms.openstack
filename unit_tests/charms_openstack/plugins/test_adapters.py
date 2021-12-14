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

# Note that the unit_tests/__init__.py has the following lines to stop
# side effects from the imorts from charm helpers.

# sys.path.append('./lib')
# mock out some charmhelpers libraries as they have apt install side effects
# sys.modules['charmhelpers.contrib.openstack.utils'] = mock.MagicMock()
# sys.modules['charmhelpers.contrib.network.ip'] = mock.MagicMock()

import unittest
from unittest import mock

import charms_openstack.adapters as c_adapters
import charms_openstack.plugins.adapters as pl_adapters


class FakeCephClientRelation():

    relation_name = 'storage-ceph'

    def mon_hosts(self):
        return ['c', 'b', 'a']


class TestCephRelationAdapter(unittest.TestCase):

    def test_class(self):
        test_config = {}
        with mock.patch.object(c_adapters.hookenv, 'related_units',
                               return_value=[]), \
                mock.patch.object(c_adapters.hookenv,
                                  'config',
                                  new=lambda: test_config):
            interface_ceph = FakeCephClientRelation()
            adapter_ceph = pl_adapters.CephRelationAdapter(
                relation=interface_ceph)
            self.assertEqual(adapter_ceph.monitors, 'a,b,c')
