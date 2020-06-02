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

import unit_tests.utils as utils

import charms_openstack.sdn.ovs as ovs


class TestCharmOpenStackSDNOVS(utils.BaseTestCase):

    def test_set_manager(self):
        self.patch_object(ovs, 'subprocess')
        ovs.set_manager('myurl')
        self.subprocess.check_call.assert_called_once_with(
            ['ovs-vsctl', 'set-manager', 'myurl'])

    def test__get_ovstbl(self):
        self.patch_object(ovs, 'subprocess')
        self.subprocess.check_output.return_value = 'ovstbl'
        self.assertEqual(ovs._get_ovstbl(), 'ovstbl')
        self.subprocess.check_output.assert_called_once_with(
            ['ovs-vsctl', 'get', 'Open_vSwitch', '.', '_uuid'])

    def test_set_config(self):
        self.patch_object(ovs, 'subprocess')
        self.patch_object(ovs, '_get_ovstbl')
        self._get_ovstbl.return_value = 'a_uuid'
        ovs.set_config('mykey', 'myvalue', 'mytable')
        self.subprocess.check_call.assert_called_once_with(
            ['ovs-vsctl', 'set', 'Open_vSwitch', 'a_uuid',
             'mytable:mykey=myvalue'])
