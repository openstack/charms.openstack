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
from unittest import mock

import charms_openstack.devices.pci as pci
import unit_tests.pci_responses as pci_responses
import unit_tests.utils as utils


def mocked_subprocess(subproc_map=None):
    def _subproc(cmd, stdin=None):
        for key in pci_responses.COMMANDS.keys():
            if pci_responses.COMMANDS[key] == cmd:
                return subproc_map[key]
            elif pci_responses.COMMANDS[key] == cmd[:-1]:
                return subproc_map[cmd[-1]][key]

    if not subproc_map:
        subproc_map = pci_responses.NET_SETUP
    return _subproc


class mocked_filehandle(object):
    def _setfilename(self, fname, omode):
        self.FILENAME = fname

    def _getfilecontents_read(self):
        return pci_responses.FILE_CONTENTS[self.FILENAME]

    def _getfilecontents_readlines(self):
        return pci_responses.FILE_CONTENTS[self.FILENAME].split('\n')


class PCIDevTest(utils.BaseTestCase):

    def test_format_pci_addr(self):
        self.assertEqual(pci.format_pci_addr('0:0:1.1'), '0000:00:01.1')
        self.assertEqual(pci.format_pci_addr(
            '0000:00:02.1'), '0000:00:02.1')


class PCINetDeviceTest(utils.BaseTestCase):

    def test_init(self):
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        a = pci.PCINetDevice('pciaddr')
        self.update_attributes.assert_called_once_with()
        self.assertEqual(a.pci_address, 'pciaddr')

    def test_update_attributes(self):
        self.patch_object(pci.PCINetDevice, '__init__')
        self.patch_object(pci.PCINetDevice, 'loaded_kmod')
        self.patch_object(pci.PCINetDevice, 'update_modalias_kmod')
        self.patch_object(pci.PCINetDevice, 'update_interface_info')
        a = pci.PCINetDevice('pciaddr')
        a.update_attributes()
        self.update_modalias_kmod.assert_called_once_with()
        self.update_interface_info.assert_called_once_with()

    def test_loaded_kmod(self):
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        self.patch_object(pci, 'subprocess')
        self.subprocess.check_output.side_effect = mocked_subprocess()
        device = pci.PCINetDevice('0000:06:00.0')
        self.assertEqual(device.loaded_kmod, 'igb_uio')

    def test_update_modalias_kmod(self):
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        self.patch_object(pci, 'subprocess')
        device = pci.PCINetDevice('0000:07:00.0')
        self.subprocess.check_output.side_effect = mocked_subprocess()
        with utils.patch_open() as (_open, _file):
            super_fh = mocked_filehandle()
            _file.readlines = mock.MagicMock()
            _open.side_effect = super_fh._setfilename
            _file.read.side_effect = super_fh._getfilecontents_read
            _file.readlines.side_effect = super_fh._getfilecontents_readlines
            device.update_modalias_kmod()
        self.assertEqual(device.modalias_kmod, 'enic')

    def test_update_interface_info_call_vpeinfo(self):
        self.patch_object(pci.PCINetDevice, 'update_interface_info_eth')
        self.patch_object(pci.PCINetDevice, 'update_interface_info_vpe')
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        self.patch_object(pci.PCINetDevice, 'get_kernel_name')
        self.patch_object(pci.PCINetDevice, 'loaded_kmod', new='igb_uio')
        self.patch_object(pci, 'subprocess')
        self.get_kernel_name.return_value = '3.13.0-77-generic'
        self.subprocess.check_output.side_effect = \
            mocked_subprocess()
        dev6 = pci.PCINetDevice('0000:06:00.0')
        dev6.update_interface_info()
        self.update_interface_info_vpe.assert_called_with()
        self.assertFalse(self.update_interface_info_eth.called)

    def test_update_interface_info_call_ethinfo(self):
        self.patch_object(pci.PCINetDevice, 'update_interface_info_eth')
        self.patch_object(pci.PCINetDevice, 'update_interface_info_vpe')
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        self.patch_object(pci.PCINetDevice, 'get_kernel_name')
        self.patch_object(pci.PCINetDevice, 'loaded_kmod', new='igb')
        self.patch_object(pci, 'subprocess')
        self.get_kernel_name.return_value = '3.13.0-77-generic'
        self.subprocess.check_output.side_effect = \
            mocked_subprocess()
        dev = pci.PCINetDevice('0000:10:00.0')
        dev.update_interface_info()
        self.update_interface_info_eth.assert_called_with()
        self.assertFalse(self.update_interface_info_vpe.called)

    def test_test_update_interface_info_orphan(self):
        self.patch_object(pci.PCINetDevice, 'update_interface_info_eth')
        self.patch_object(pci.PCINetDevice, 'update_interface_info_vpe')
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        self.patch_object(pci.PCINetDevice, 'get_kernel_name')
        self.patch_object(pci, 'subprocess')
        self.subprocess.check_output.side_effect = \
            mocked_subprocess(
                subproc_map=pci_responses.NET_SETUP_ORPHAN)
        dev = pci.PCINetDevice('0000:07:00.0')
        dev.update_interface_info()
        self.assertFalse(self.update_interface_info_vpe.called)
        self.assertFalse(self.update_interface_info_eth.called)
        self.assertEqual(dev.interface_name, None)
        self.assertEqual(dev.mac_address, None)

    def test_get_kernel_name(self):
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        self.patch_object(pci, 'subprocess')
        dev = pci.PCINetDevice('0000:07:00.0')
        self.subprocess.check_output.return_value = '3.13.0-55-generic'
        self.assertEqual(dev.get_kernel_name(), '3.13.0-55-generic')

    def test_pci_rescan(self):
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        self.patch_object(pci, 'subprocess')
        dev = pci.PCINetDevice('0000:07:00.0')
        with utils.patch_open() as (_open, _file):
            dev.pci_rescan()
            _open.assert_called_with('/sys/bus/pci/rescan', 'w')
            _file.write.assert_called_with('1')

    def test_bind(self):
        self.patch_object(pci.PCINetDevice, 'pci_rescan')
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        dev = pci.PCINetDevice('0000:07:00.0')
        with utils.patch_open() as (_open, _file):
            dev.bind('enic')
            _open.assert_called_with('/sys/bus/pci/drivers/enic/bind', 'w')
            _file.write.assert_called_with('0000:07:00.0')
        self.pci_rescan.assert_called_with()
        self.update_attributes.assert_called_with()

    def test_unbind(self):
        self.patch_object(pci.PCINetDevice, 'pci_rescan')
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        self.patch_object(pci.PCINetDevice, 'loaded_kmod', new='igb_uio')
        dev = pci.PCINetDevice('0000:07:00.0')
        with utils.patch_open() as (_open, _file):
            dev.unbind()
            _open.assert_called_with(
                '/sys/bus/pci/drivers/igb_uio/unbind', 'w')
            _file.write.assert_called_with('0000:07:00.0')
        self.pci_rescan.assert_called_with()
        self.update_attributes.assert_called_with()

    def test_update_interface_info_vpe(self):
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        self.patch_object(pci.PCINetDevice, 'get_vpe_interfaces_and_macs')
        self.get_vpe_interfaces_and_macs.return_value = [
            {
                'interface': 'TenGigabitEthernet6/0/0',
                'macAddress': '84:b8:02:2a:5f:c3',
                'pci_address': '0000:06:00.0'},
            {
                'interface': 'TenGigabitEthernet7/0/0',
                'macAddress': '84:b8:02:2a:5f:c4',
                'pci_address': '0000:07:00.0'}]
        dev = pci.PCINetDevice('0000:07:00.0')
        dev.update_interface_info_vpe()
        self.assertEqual('TenGigabitEthernet7/0/0', dev.interface_name)
        self.assertEqual('84:b8:02:2a:5f:c4', dev.mac_address)
        self.assertEqual('vpebound', dev.state)

    def test_update_interface_info_vpe_orphan(self):
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        self.patch_object(pci.PCINetDevice, 'get_vpe_interfaces_and_macs')
        self.get_vpe_interfaces_and_macs.return_value = [
            {
                'interface': 'TenGigabitEthernet6/0/0',
                'macAddress': '84:b8:02:2a:5f:c3',
                'pci_address': '0000:06:00.0'}]
        dev = pci.PCINetDevice('0000:07:00.0')
        dev.update_interface_info_vpe()
        self.assertEqual(None, dev.interface_name)
        self.assertEqual(None, dev.mac_address)
        self.assertEqual(None, dev.state)

    def test_get_vpe_cli_out(self):
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        self.patch_object(pci, 'subprocess')
        self.subprocess.check_output.side_effect = \
            mocked_subprocess()
        dev = pci.PCINetDevice('0000:07:00.0')
        self.assertTrue('local0' in dev.get_vpe_cli_out())

    def test_get_vpe_interfaces_and_macs(self):
        self.patch_object(pci.PCINetDevice, 'get_vpe_cli_out')
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        self.patch_object(pci, 'subprocess')
        self.subprocess.check_output.side_effect = \
            mocked_subprocess()
        self.get_vpe_cli_out.return_value = pci_responses.CONFD_CLI
        dev = pci.PCINetDevice('0000:07:00.0')
        vpe_devs = dev.get_vpe_interfaces_and_macs()
        expect = [
            {
                'interface': 'TenGigabitEthernet6/0/0',
                'macAddress': '84:b8:02:2a:5f:c3',
                'pci_address': '0000:06:00.0'
            },
            {
                'interface': 'TenGigabitEthernet7/0/0',
                'macAddress': '84:b8:02:2a:5f:c4',
                'pci_address': '0000:07:00.0'
            },
        ]
        self.assertEqual(vpe_devs, expect)

    def test_get_vpe_interfaces_and_macs_invalid_cli(self):
        self.patch_object(pci.PCINetDevice, 'get_vpe_cli_out')
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        self.patch_object(pci, 'subprocess')
        self.subprocess.check_output.side_effect = \
            mocked_subprocess()
        dev = pci.PCINetDevice('0000:07:00.0')
        self.get_vpe_cli_out.return_value = pci_responses.CONFD_CLI_NOLOCAL
        with self.assertRaises(pci.VPECLIException):
            dev.get_vpe_interfaces_and_macs()

    def test_get_vpe_interfaces_and_macs_invmac(self):
        self.patch_object(pci.PCINetDevice, 'get_vpe_cli_out')
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        self.patch_object(pci, 'subprocess')
        self.subprocess.check_output.side_effect = \
            mocked_subprocess()
        dev = pci.PCINetDevice('0000:07:00.0')
        self.get_vpe_cli_out.return_value = pci_responses.CONFD_CLI_INVMAC
        vpe_devs = dev.get_vpe_interfaces_and_macs()
        expect = [
            {
                'interface': 'TenGigabitEthernet7/0/0',
                'macAddress': '84:b8:02:2a:5f:c4',
                'pci_address': '0000:07:00.0'
            },
        ]
        self.assertEqual(vpe_devs, expect)

    def test_extract_pci_addr_from_vpe_interface(self):
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        dev = pci.PCINetDevice('0000:07:00.0')
        self.assertEqual(dev.extract_pci_addr_from_vpe_interface(
            'TenGigabitEthernet1/1/1'), '0000:01:01.1')
        self.assertEqual(dev.extract_pci_addr_from_vpe_interface(
            'TenGigabitEtherneta/0/0'), '0000:0a:00.0')
        self.assertEqual(dev.extract_pci_addr_from_vpe_interface(
            'GigabitEthernet0/2/0'), '0000:00:02.0')

    def test_update_interface_info_eth(self):
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        self.patch_object(pci.PCINetDevice, 'get_sysnet_interfaces_and_macs')
        dev = pci.PCINetDevice('0000:10:00.0')
        self.get_sysnet_interfaces_and_macs.return_value = [
            {
                'interface': 'eth2',
                'macAddress': 'a8:9d:21:cf:93:fc',
                'pci_address': '0000:10:00.0',
                'state': 'up'
            },
            {
                'interface': 'eth3',
                'macAddress': 'a8:9d:21:cf:93:fd',
                'pci_address': '0000:10:00.1',
                'state': 'down'
            }
        ]
        dev.update_interface_info_eth()
        self.assertEqual(dev.interface_name, 'eth2')

    def test_get_sysnet_interfaces_and_macs_virtio(self):
        self.patch_object(pci.glob, 'glob')
        self.patch_object(pci.os.path, 'islink')
        self.patch_object(pci.os.path, 'realpath')
        self.patch_object(pci.PCINetDevice, 'get_sysnet_device_state')
        self.patch_object(pci.PCINetDevice, 'get_sysnet_mac')
        self.patch_object(pci.PCINetDevice, 'get_sysnet_interface')
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        dev = pci.PCINetDevice('0000:06:00.0')
        self.glob.return_value = ['/sys/class/net/eth2']
        self.get_sysnet_interface.return_value = 'eth2'
        self.get_sysnet_mac.return_value = 'a8:9d:21:cf:93:fc'
        self.get_sysnet_device_state.return_value = 'up'
        self.realpath.return_value = ('/sys/devices/pci0000:00/0000:00:07.0/'
                                      'virtio5')
        self.islink.return_value = True
        expect = {
            'interface': 'eth2',
            'macAddress': 'a8:9d:21:cf:93:fc',
            'pci_address': '0000:00:07.0',
            'state': 'up',
        }
        self.assertEqual(dev.get_sysnet_interfaces_and_macs(), [expect])

    def test_get_sysnet_interfaces_and_macs(self):
        self.patch_object(pci.glob, 'glob')
        self.patch_object(pci.os.path, 'islink')
        self.patch_object(pci.os.path, 'realpath')
        self.patch_object(pci.PCINetDevice, 'get_sysnet_device_state')
        self.patch_object(pci.PCINetDevice, 'get_sysnet_mac')
        self.patch_object(pci.PCINetDevice, 'get_sysnet_interface')
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        dev = pci.PCINetDevice('0000:06:00.0')
        self.glob.return_value = ['/sys/class/net/eth2']
        self.get_sysnet_interface.return_value = 'eth2'
        self.get_sysnet_mac.return_value = 'a8:9d:21:cf:93:fc'
        self.get_sysnet_device_state.return_value = 'up'
        self.realpath.return_value = (
            '/sys/devices/pci0000:00/0000:00:02.0/0000:02:00.0/0000:03:00.0/'
            '0000:04:00.0/0000:05:01.0/0000:07:00.0')
        self.islink.return_value = True
        expect = {
            'interface': 'eth2',
            'macAddress': 'a8:9d:21:cf:93:fc',
            'pci_address': '0000:07:00.0',
            'state': 'up',
        }
        self.assertEqual(dev.get_sysnet_interfaces_and_macs(), [expect])

    def test_get_sysnet_mac(self):
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        device = pci.PCINetDevice('0000:10:00.1')
        with utils.patch_open() as (_open, _file):
            super_fh = mocked_filehandle()
            _file.readlines = mock.MagicMock()
            _open.side_effect = super_fh._setfilename
            _file.read.side_effect = super_fh._getfilecontents_read
            macaddr = device.get_sysnet_mac('/sys/class/net/eth3')
        self.assertEqual(macaddr, 'a8:9d:21:cf:93:fd')

    def test_get_sysnet_device_state(self):
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        device = pci.PCINetDevice('0000:10:00.1')
        with utils.patch_open() as (_open, _file):
            super_fh = mocked_filehandle()
            _file.readlines = mock.MagicMock()
            _open.side_effect = super_fh._setfilename
            _file.read.side_effect = super_fh._getfilecontents_read
            state = device.get_sysnet_device_state('/sys/class/net/eth3')
        self.assertEqual(state, 'down')

    def test_get_sysnet_interface(self):
        self.patch_object(pci.PCINetDevice, 'update_attributes')
        device = pci.PCINetDevice('0000:10:00.1')
        self.assertEqual(
            device.get_sysnet_interface('/sys/class/net/eth3'), 'eth3')


class PCINetDevicesTest(utils.BaseTestCase):

    def test_init(self):
        self.patch_object(pci.PCINetDevices, 'get_pci_ethernet_addresses')
        self.patch_object(pci, 'PCINetDevice')
        self.get_pci_ethernet_addresses.return_value = ['pciaddr']
        pci.PCINetDevices()
        self.PCINetDevice.assert_called_once_with('pciaddr')

    def test_get_pci_ethernet_addresses(self):
        self.patch_object(pci, 'subprocess')
        self.patch_object(pci, 'PCINetDevice')
        self.subprocess.check_output.side_effect = \
            mocked_subprocess()
        a = pci.PCINetDevices()
        self.assertEqual(
            a.get_pci_ethernet_addresses(),
            ['0000:06:00.0', '0000:07:00.0', '0000:10:00.0', '0000:10:00.1'])

    def test_update_devices(self):
        pcinetdev = mock.MagicMock()
        self.patch_object(pci.PCINetDevices, 'get_pci_ethernet_addresses')
        self.patch_object(pci, 'PCINetDevice')
        self.PCINetDevice.return_value = pcinetdev
        self.get_pci_ethernet_addresses.return_value = ['pciaddr']
        a = pci.PCINetDevices()
        a.update_devices()
        pcinetdev.update_attributes.assert_called_once_with()

    def test_get_macs(self):
        pcinetdev = mock.MagicMock()
        self.patch_object(pci.PCINetDevices, 'get_pci_ethernet_addresses')
        self.patch_object(pci, 'PCINetDevice')
        self.PCINetDevice.return_value = pcinetdev
        self.get_pci_ethernet_addresses.return_value = ['pciaddr']
        pcinetdev.mac_address = 'mac1'
        a = pci.PCINetDevices()
        self.assertEqual(a.get_macs(), ['mac1'])

    def test_get_device_from_mac(self):
        pcinetdev = mock.MagicMock()
        self.patch_object(pci.PCINetDevices, 'get_pci_ethernet_addresses')
        self.patch_object(pci, 'PCINetDevice')
        self.PCINetDevice.return_value = pcinetdev
        self.get_pci_ethernet_addresses.return_value = ['pciaddr']
        pcinetdev.mac_address = 'mac1'
        a = pci.PCINetDevices()
        self.assertEqual(a.get_device_from_mac('mac1'), pcinetdev)

    def test_get_device_from_pci_address(self):
        pcinetdev = mock.MagicMock()
        self.patch_object(pci.PCINetDevices, 'get_pci_ethernet_addresses')
        self.patch_object(pci, 'PCINetDevice')
        self.PCINetDevice.return_value = pcinetdev
        self.get_pci_ethernet_addresses.return_value = ['pciaddr']
        pcinetdev.pci_address = 'pciaddr'
        a = pci.PCINetDevices()
        self.assertEqual(a.get_device_from_pci_address('pciaddr'), pcinetdev)

    def test_rebind_orphans(self):
        self.patch_object(pci.PCINetDevices, 'get_pci_ethernet_addresses')
        self.patch_object(pci.PCINetDevices, 'unbind_orphans')
        self.patch_object(pci.PCINetDevices, 'bind_orphans')
        self.patch_object(pci, 'PCINetDevice')
        self.get_pci_ethernet_addresses.return_value = []
        a = pci.PCINetDevices()
        a.rebind_orphans()
        self.unbind_orphans.assert_called_once_with()
        self.bind_orphans.assert_called_once_with()

    def test_unbind_orphans(self):
        orphan = mock.MagicMock()
        self.patch_object(pci.PCINetDevices, 'get_pci_ethernet_addresses')
        self.get_pci_ethernet_addresses.return_value = ['pciaddr']
        self.patch_object(pci.PCINetDevices, 'get_orphans')
        self.patch_object(pci.PCINetDevices, 'update_devices')
        self.patch_object(pci, 'PCINetDevice')
        self.get_orphans.return_value = [orphan]
        a = pci.PCINetDevices()
        a.unbind_orphans()
        orphan.unbind.assert_called_once_with()
        self.update_devices.assert_called_once_with()

    def test_bind_orphans(self):
        orphan = mock.MagicMock()
        self.patch_object(pci.PCINetDevices, 'get_pci_ethernet_addresses')
        self.get_pci_ethernet_addresses.return_value = ['pciaddr']
        self.patch_object(pci.PCINetDevices, 'get_orphans')
        self.patch_object(pci.PCINetDevices, 'update_devices')
        self.patch_object(pci, 'PCINetDevice')
        self.get_orphans.return_value = [orphan]
        orphan.modalias_kmod = 'kmod'
        a = pci.PCINetDevices()
        a.bind_orphans()
        orphan.bind.assert_called_once_with('kmod')
        self.update_devices.assert_called_once_with()

    def test_get_orphans(self):
        pcinetdev = mock.MagicMock()
        self.patch_object(pci.PCINetDevices, 'get_pci_ethernet_addresses')
        self.patch_object(pci, 'PCINetDevice')
        self.PCINetDevice.return_value = pcinetdev
        self.get_pci_ethernet_addresses.return_value = ['pciaddr']
        pcinetdev.loaded_kmod = None
        pcinetdev.interface_name = None
        pcinetdev.mac_address = None
        a = pci.PCINetDevices()
        self.assertEqual(a.get_orphans(), [pcinetdev])


class PCIInfoTest(utils.BaseTestCase):

    def dev_mock(self, state, pci_address, interface_name):
        dev = mock.MagicMock()
        dev.state = state
        dev.pci_address = pci_address
        dev.interface_name = interface_name
        return dev

    def test_init(self):
        net_dev_mocks = {
            'mac1': self.dev_mock('down', 'pciaddr0', 'eth0'),
            'mac2': self.dev_mock('down', 'pciaddr1', 'eth1'),
            'mac3': self.dev_mock('up', 'pciaddr3', 'eth2'),
        }
        net_devs = mock.MagicMock()
        self.patch_object(pci.PCIInfo, 'get_user_requested_config')
        self.patch_object(pci, 'PCINetDevices')
        self.PCINetDevices.return_value = net_devs
        net_devs.get_macs.return_value = net_dev_mocks.keys()
        net_devs.get_device_from_mac.side_effect = lambda x: net_dev_mocks[x]
        self.get_user_requested_config.return_value = {
            'mac1': [{'net': 'net1'}, {'net': 'net2'}],
            'mac2': [{'net': 'net1'}],
            'mac3': [{'net': 'net1'}]}
        a = pci.PCIInfo()
        expect = {
            'mac1': [{'interface': 'eth0', 'net': 'net1'},
                     {'interface': 'eth0', 'net': 'net2'}],
            'mac2': [{'interface': 'eth1', 'net': 'net1'}]}
        self.assertEqual(a.local_mac_nets, expect)
        self.assertEqual(a.vpe_dev_string, 'dev pciaddr0 dev pciaddr1')

    def test_get_user_requested_config(self):
        self.patch_object(pci.PCIInfo, '__init__')
        self.patch_object(pci.hookenv, 'config')
        self.config.return_value = ('mac=mac1;net=net1 mac=mac1;net=net2'
                                    ' mac=mac2;net=net1')
        a = pci.PCIInfo()
        expect = {
            'mac1': [{'net': 'net1'}, {'net': 'net2'}],
            'mac2': [{'net': 'net1'}]}
        self.assertEqual(a.get_user_requested_config(), expect)

    def test_get_user_requested_invalid_entries(self):
        self.patch_object(pci.PCIInfo, '__init__')
        self.patch_object(pci.hookenv, 'config')
        self.config.return_value = ('ac=mac1;net=net1 randomstuff'
                                    ' mac=mac2;net=net1')
        a = pci.PCIInfo()
        expect = {'mac2': [{'net': 'net1'}]}
        self.assertEqual(a.get_user_requested_config(), expect)

    def test_get_user_requested_config_empty(self):
        self.patch_object(pci.PCIInfo, '__init__')
        self.patch_object(pci.hookenv, 'config')
        self.config.return_value = None
        a = pci.PCIInfo()
        expect = {}
        self.assertEqual(a.get_user_requested_config(), expect)
