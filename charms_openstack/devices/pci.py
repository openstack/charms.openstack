import re
import os
import glob
import shlex
import subprocess

import charmhelpers.core.decorators as decorators
import charmhelpers.core.hookenv as hookenv


def format_pci_addr(pci_addr):
    """Pad a PCI address eg 0:0:1.1 becomes 0000:00:01.1

    :param pci_addr: str
    :return pci_addr: str
    """
    domain, bus, slot_func = pci_addr.split(':')
    slot, func = slot_func.split('.')
    return '{}:{}:{}.{}'.format(domain.zfill(4), bus.zfill(2), slot.zfill(2),
                                func)


class VPECLIException(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message


class PCINetDevice(object):

    def __init__(self, pci_address):
        """Class representing a PCI device

        :param pci_addr: str PCI address of device
        """
        self.pci_address = pci_address
        self.update_attributes()

    def update_attributes(self):
        """Query the underlying system and update attributes of this device
        """
        self.update_modalias_kmod()
        self.update_interface_info()

    @property
    def loaded_kmod(self):
        """Return Kernel module this device is using

        :returns str: Kernel module
        """
        cmd = ['lspci', '-ks', self.pci_address]
        lspci_output = subprocess.check_output(cmd)
        kdrive = None
        for line in lspci_output.split('\n'):
            if 'Kernel driver' in line:
                kdrive = line.split(':')[1].strip()
        hookenv.log('Loaded kmod for {} is {}'.format(
            self.pci_address, kdrive))
        return kdrive

    def update_modalias_kmod(self):
        """Set the default kernel module for this device

        If a device is orphaned it has no kernel module loaded to support it
        so look up the device in modules.alias and set the kernel module
        it needs"""

        cmd = ['lspci', '-ns', self.pci_address]
        lspci_output = subprocess.check_output(cmd).split()
        vendor_device = lspci_output[2]
        vendor, device = vendor_device.split(':')
        pci_string = 'pci:v{}d{}'.format(vendor.zfill(8), device.zfill(8))
        kernel_name = self.get_kernel_name()
        alias_files = '/lib/modules/{}/modules.alias'.format(kernel_name)
        kmod = None
        with open(alias_files, 'r') as f:
            for line in f.readlines():
                if pci_string in line:
                    kmod = line.split()[-1]
        hookenv.log('module.alias kmod for {} is {}'.format(
            self.pci_address, kmod))
        self.modalias_kmod = kmod

    def update_interface_info(self):
        """Set the interface name, mac address and state properties of this
           object"""
        if self.loaded_kmod:
            if self.loaded_kmod == 'igb_uio':
                return self.update_interface_info_vpe()
            else:
                return self.update_interface_info_eth()
        else:
            self.interface_name = None
            self.mac_address = None
            self.state = 'unbound'

    def get_kernel_name(self):
        """Return the kernel release of the running kernel

        :returns str: Kernel release
        """
        return subprocess.check_output(['uname', '-r']).strip()

    def pci_rescan(self):
        """Rescan of all PCI buses in the system, and
        re-discover previously removed devices."""
        rescan_file = '/sys/bus/pci/rescan'
        with open(rescan_file, 'w') as f:
            f.write('1')

    def bind(self, kmod):
        """Write PCI address to the bind file to cause the driver to attempt to
        bind to the device found at the PCI address. This is useful for
        overriding default bindings."""
        bind_file = '/sys/bus/pci/drivers/{}/bind'.format(kmod)
        hookenv.log('Binding {} to {}'.format(self.pci_address, bind_file))
        with open(bind_file, 'w') as f:
            f.write(self.pci_address)
        self.pci_rescan()
        self.update_attributes()

    def unbind(self):
        """Write PCI address to the unbind file to cause the driver to attempt
        to unbind the device found at at the PCI address."""
        if not self.loaded_kmod:
            return
        unbind_file = '/sys/bus/pci/drivers/{}/unbind'.format(self.loaded_kmod)
        hookenv.log('Unbinding {} from {}'.format(
            self.pci_address, unbind_file))
        with open(unbind_file, 'w') as f:
            f.write(self.pci_address)
        self.pci_rescan()
        self.update_attributes()

    def update_interface_info_vpe(self):
        """Query VPE CLI to set the interface name, mac address and state
           properties of this device"""
        vpe_devices = self.get_vpe_interfaces_and_macs()
        device_info = {}
        for interface in vpe_devices:
            if self.pci_address == interface['pci_address']:
                device_info['interface'] = interface['interface']
                device_info['macAddress'] = interface['macAddress']
        if device_info:
            self.interface_name = device_info['interface']
            self.mac_address = device_info['macAddress']
            self.state = 'vpebound'
        else:
            self.interface_name = None
            self.mac_address = None
            self.state = None

    @decorators.retry_on_exception(5, base_delay=10,
                                   exc_type=subprocess.CalledProcessError)
    def get_vpe_cli_out(self):
        """Query VPE CLI and dump interface information

        :returns str: confd_cli output"""
        echo_cmd = [
            'echo', '-e', 'show interfaces-state interface phys-address\nexit']
        cli_cmd = ['/opt/cisco/vpe/bin/confd_cli', '-N', '-C', '-u', 'system']
        echo = subprocess.Popen(echo_cmd, stdout=subprocess.PIPE)
        cli_output = subprocess.check_output(cli_cmd, stdin=echo.stdout)
        echo.wait()
        echo.terminate
        hookenv.log('confd_cli: ' + cli_output)
        return cli_output

    def get_vpe_interfaces_and_macs(self):
        """Parse output from VPE CLI and retrun list of interface data dicts

        :returns list: list of dicts of interface data
        eg [
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
        """
        cli_output = self.get_vpe_cli_out()
        vpe_devs = []
        if 'local0' not in cli_output:
            msg = ('local0 missing from confd_cli output, assuming things '
                   'went wrong')
            raise VPECLIException(1, msg)
        for line in cli_output.split('\n'):
            if re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', line, re.I):
                interface, mac = line.split()
                pci_addr = self.extract_pci_addr_from_vpe_interface(interface)
                vpe_devs.append({
                    'interface': interface,
                    'macAddress': mac,
                    'pci_address': pci_addr,
                })
        return vpe_devs

    def extract_pci_addr_from_vpe_interface(self, nic):
        """Convert a str from nic postfix format to padded format

        :returns list: list of dicts of interface data

        eg 6/1/2 -> 0000:06:01.2"""
        hookenv.log('Extracting pci address from {}'.format(nic))
        addr = re.sub(r'^.*Ethernet', '', nic, re.IGNORECASE)
        bus, slot, func = addr.split('/')
        domain = '0000'
        pci_addr = format_pci_addr(
            '{}:{}:{}.{}'.format(domain, bus, slot, func))
        hookenv.log('pci address for {} is {}'.format(nic, pci_addr))
        return pci_addr

    def update_interface_info_eth(self):
        """Set the interface name, mac address and state
           properties of this device if device is in sys fs"""
        net_devices = self.get_sysnet_interfaces_and_macs()
        for interface in net_devices:
            if self.pci_address == interface['pci_address']:
                self.interface_name = interface['interface']
                self.mac_address = interface['macAddress']
                self.state = interface['state']

    def get_sysnet_interfaces_and_macs(self):
        """Query sys fs and retrun list of interface data dicts
        eg [
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
        """
        net_devs = []
        for sdir in glob.glob('/sys/class/net/*'):
            sym_link = sdir + "/device"
            if os.path.islink(sym_link):
                fq_path = os.path.realpath(sym_link)
                path = fq_path.split('/')
                if 'virtio' in path[-1]:
                    pci_address = path[-2]
                else:
                    pci_address = path[-1]
                net_devs.append({
                    'interface': self.get_sysnet_interface(sdir),
                    'macAddress': self.get_sysnet_mac(sdir),
                    'pci_address': pci_address,
                    'state': self.get_sysnet_device_state(sdir),
                })
        return net_devs

    def get_sysnet_mac(self, sysdir):
        """Extract MAC address from sys device file

        :returns str: mac address"""
        mac_addr_file = sysdir + '/address'
        with open(mac_addr_file, 'r') as f:
            read_data = f.read()
        mac = read_data.strip()
        hookenv.log('mac from {} is {}'.format(mac_addr_file, mac))
        return mac

    def get_sysnet_device_state(self, sysdir):
        """Extract device state from sys device file

        :returns str: device state"""
        state_file = sysdir + '/operstate'
        with open(state_file, 'r') as f:
            read_data = f.read()
        state = read_data.strip()
        hookenv.log('state from {} is {}'.format(state_file, state))
        return state

    def get_sysnet_interface(self, sysdir):
        """Extract device file from FQ path

        :returns str: interface name"""
        return sysdir.split('/')[-1]


class PCINetDevices(object):
    """PCINetDevices represents a collection of PCI Network devices on the
       running system"""

    def __init__(self):
        """Initialise a collection of PCINetDevice"""
        pci_addresses = self.get_pci_ethernet_addresses()
        self.pci_devices = [PCINetDevice(dev) for dev in pci_addresses]

    def get_pci_ethernet_addresses(self):
        """Query lspci to retrieve a list of PCI address for devices of type
           'Ethernet controller'

        :returns list: List of PCI addresses of Ethernet controllers"""
        cmd = ['lspci', '-m', '-D']
        lspci_output = subprocess.check_output(cmd)
        pci_addresses = []
        for line in lspci_output.split('\n'):
            columns = shlex.split(line)
            if len(columns) > 1 and columns[1] == 'Ethernet controller':
                pci_address = columns[0]
                pci_addresses.append(format_pci_addr(pci_address))
        return pci_addresses

    def update_devices(self):
        """Update attributes of each device in collection"""
        for pcidev in self.pci_devices:
            pcidev.update_attributes()

    def get_macs(self):
        """MAC addresses of all devices in collection

        :returns list: List of MAC addresses"""
        macs = []
        for pcidev in self.pci_devices:
            if pcidev.mac_address:
                macs.append(pcidev.mac_address)
        return macs

    def get_device_from_mac(self, mac):
        """Given a MAC address return the corresponding PCINetDevice

        :returns PCINetDevice"""
        for pcidev in self.pci_devices:
            if pcidev.mac_address == mac:
                return pcidev

    def get_device_from_pci_address(self, pci_addr):
        """Given a PCI address return the corresponding PCINetDevice

        :returns PCINetDevice"""
        for pcidev in self.pci_devices:
            if pcidev.pci_address == pci_addr:
                return pcidev

    def rebind_orphans(self):
        """Unbind orphaned devices from the kernel module they are currently
           using and then bind it with its default kernel module"""
        self.unbind_orphans()
        self.bind_orphans()

    def unbind_orphans(self):
        """Unbind orphaned devices from the kernel module they are currently
           using"""
        for orphan in self.get_orphans():
            orphan.unbind()
        self.update_devices()

    def bind_orphans(self):
        """Bind orphans with their default kernel module"""
        for orphan in self.get_orphans():
            orphan.bind(orphan.modalias_kmod)
        self.update_devices()

    def get_orphans(self):
        """An 'orphan' is a device which is not fully setup. It may not be
           associated with a kernel module or may lay a name or MAC address.

        :returns list: List of PCINetDevice"""
        orphans = []
        for pcidev in self.pci_devices:
            if not pcidev.loaded_kmod or pcidev.loaded_kmod == 'igb_uio':
                if not pcidev.interface_name and not pcidev.mac_address:
                    orphans.append(pcidev)
        return orphans


class PCIInfo(object):

    def __init__(self):
        """Inspect the charm config option 'mac-network-map' against the MAC
           addresses on the running system.

           Attributes:
               user_requested_config dict Dictionary of MAC addresses and the
                                          networks they are associated with.
               local_macs            list MAC addresses on local machine
               pci_addresses         list PCI Addresses of network devices on
                                          local machine
               vpe_dev_string        str  String containing PCI addresse in
                                          format used by vpe.conf
               local_mac_nets        dict Dictionary of list of dicts with
                                          interface and netork information
                                          keyed on MAC address eg
            {
                'mac1': [{'interface': 'eth0', 'net': 'net1'},
                         {'interface': 'eth0', 'net': 'net2'}],
                'mac2': [{'interface': 'eth1', 'net': 'net1'}],}
        """
        self.user_requested_config = self.get_user_requested_config()
        net_devices = PCINetDevices()
        self.local_macs = net_devices.get_macs()
        self.pci_addresses = []
        self.local_mac_nets = {}
        for mac in self.user_requested_config.keys():
            hookenv.log('Checking if {} is on this host'.format(mac))
            if mac in self.local_macs:
                hookenv.log('{} is on this host'.format(mac))
                device = net_devices.get_device_from_mac(mac)
                hookenv.log('{} is {} and is currently {}'.format(mac,
                            device.pci_address, device.interface_name))
                if device.state == 'up':
                    hookenv.log('Refusing to add {} to device list as it is '
                                '{}'.format(device.pci_address, device.state))
                else:
                    self.pci_addresses.append(device.pci_address)
                    self.local_mac_nets[mac] = []
                    for conf in self.user_requested_config[mac]:
                        self.local_mac_nets[mac].append({
                            'net': conf.get('net'),
                            'interface': device.interface_name,
                        })
        if self.pci_addresses:
            self.pci_addresses.sort()
            self.vpe_dev_string = 'dev ' + ' dev '.join(self.pci_addresses)
        else:
            self.vpe_dev_string = 'no-pci'
        hookenv.log('vpe_dev_string {}'.format(self.vpe_dev_string))

    def parse_mmap_entry(self, conf):
        """Extract mac and net pairs from list in the form
               ['mac=mac1', 'net=net1']

        :returns tuple: (mac, net)
        """
        entry = {a.split('=')[0]: a.split('=')[1] for a in conf}
        return entry['mac'], entry['net']

    def get_user_requested_config(self):
        ''' Parse the user requested config str
        mac=<mac>;net=<net> and return a dict keyed on mac address

        :returns dict: Dictionary of MAC addresses and the networks they are
                       associated with. eg
                       mac-network-map set to 'mac=mac1;net=net1
                                               mac=mac1;net=net2
                                               mac=mac2;net=net1'
                       returns:
                           {
                               'mac1': [{'net': 'net1'}, {'net': 'net2'}],
                               'mac2': [{'net': 'net1'}]}
                           }
        '''
        mac_net_config = {}
        mac_map = hookenv.config('mac-network-map')
        if mac_map:
            for conf_group in mac_map.split():
                try:
                    mac, net = self.parse_mmap_entry(conf_group.split(';'))
                # Ignore bad config entries
                except IndexError:
                    hookenv.log('Ignoring bad config entry {} in'
                                'mac-network-map'.format(conf_group))
                    continue
                except KeyError:
                    hookenv.log('Ignoring bad config entry {} in'
                                'mac-network-map'.format(conf_group))
                    continue
                try:
                    mac_net_config[mac].append({'net': net})
                except KeyError:
                    mac_net_config[mac] = [{'net': net}]
        return mac_net_config
