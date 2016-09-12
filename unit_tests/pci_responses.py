import copy
# flake8: noqa
LSPCI = """
0000:00:00.0 "Host bridge" "Intel Corporation" "Haswell-E DMI2" -r02 "Intel Corporation" "Device 0000"
0000:00:03.0 "PCI bridge" "Intel Corporation" "Haswell-E PCI Express Root Port 3" -r02 "" ""
0000:00:03.2 "PCI bridge" "Intel Corporation" "Haswell-E PCI Express Root Port 3" -r02 "" ""
0000:00:05.0 "System peripheral" "Intel Corporation" "Haswell-E Address Map, VTd_Misc, System Management" -r02 "" ""
0000:00:05.1 "System peripheral" "Intel Corporation" "Haswell-E Hot Plug" -r02 "" ""
0000:00:05.2 "System peripheral" "Intel Corporation" "Haswell-E RAS, Control Status and Global Errors" -r02 "" ""
0000:00:05.4 "PIC" "Intel Corporation" "Haswell-E I/O Apic" -r02 -p20 "Intel Corporation" "Device 0000"
0000:00:11.0 "Unassigned class [ff00]" "Intel Corporation" "Wellsburg SPSR" -r05 "Intel Corporation" "Device 7270"
0000:00:11.4 "SATA controller" "Intel Corporation" "Wellsburg sSATA Controller [AHCI mode]" -r05 -p01 "Cisco Systems Inc" "Device 0067"
0000:00:16.0 "Communication controller" "Intel Corporation" "Wellsburg MEI Controller #1" -r05 "Intel Corporation" "Device 7270"
0000:00:16.1 "Communication controller" "Intel Corporation" "Wellsburg MEI Controller #2" -r05 "Intel Corporation" "Device 7270"
0000:00:1a.0 "USB controller" "Intel Corporation" "Wellsburg USB Enhanced Host Controller #2" -r05 -p20 "Intel Corporation" "Device 7270"
0000:00:1c.0 "PCI bridge" "Intel Corporation" "Wellsburg PCI Express Root Port #1" -rd5 "" ""
0000:00:1c.3 "PCI bridge" "Intel Corporation" "Wellsburg PCI Express Root Port #4" -rd5 "" ""
0000:00:1c.4 "PCI bridge" "Intel Corporation" "Wellsburg PCI Express Root Port #5" -rd5 "" ""
0000:00:1d.0 "USB controller" "Intel Corporation" "Wellsburg USB Enhanced Host Controller #1" -r05 -p20 "Intel Corporation" "Device 7270"
0000:00:1f.0 "ISA bridge" "Intel Corporation" "Wellsburg LPC Controller" -r05 "Intel Corporation" "Device 7270"
0000:00:1f.2 "SATA controller" "Intel Corporation" "Wellsburg 6-Port SATA Controller [AHCI mode]" -r05 -p01 "Cisco Systems Inc" "Device 0067"
0000:01:00.0 "PCI bridge" "Cisco Systems Inc" "VIC 82 PCIe Upstream Port" -r01 "" ""
0000:02:00.0 "PCI bridge" "Cisco Systems Inc" "VIC PCIe Downstream Port" -ra2 "" ""
0000:02:01.0 "PCI bridge" "Cisco Systems Inc" "VIC PCIe Downstream Port" -ra2 "" ""
0000:03:00.0 "Unclassified device [00ff]" "Cisco Systems Inc" "VIC Management Controller" -ra2 "Cisco Systems Inc" "Device 012e"
0000:04:00.0 "PCI bridge" "Cisco Systems Inc" "VIC PCIe Upstream Port" -ra2 "" ""
0000:05:00.0 "PCI bridge" "Cisco Systems Inc" "VIC PCIe Downstream Port" -ra2 "" ""
0000:05:01.0 "PCI bridge" "Cisco Systems Inc" "VIC PCIe Downstream Port" -ra2 "" ""
0000:05:02.0 "PCI bridge" "Cisco Systems Inc" "VIC PCIe Downstream Port" -ra2 "" ""
0000:05:03.0 "PCI bridge" "Cisco Systems Inc" "VIC PCIe Downstream Port" -ra2 "" ""
0000:06:00.0 "Ethernet controller" "Cisco Systems Inc" "VIC Ethernet NIC" -ra2 "Cisco Systems Inc" "Device 012e"
0000:07:00.0 "Ethernet controller" "Cisco Systems Inc" "VIC Ethernet NIC" -ra2 "Cisco Systems Inc" "Device 012e"
0000:08:00.0 "Fibre Channel" "Cisco Systems Inc" "VIC FCoE HBA" -ra2 "Cisco Systems Inc" "Device 012e"
0000:09:00.0 "Fibre Channel" "Cisco Systems Inc" "VIC FCoE HBA" -ra2 "Cisco Systems Inc" "Device 012e"
0000:0b:00.0 "RAID bus controller" "LSI Logic / Symbios Logic" "MegaRAID SAS-3 3108 [Invader]" -r02 "Cisco Systems Inc" "Device 00db"
0000:0f:00.0 "VGA compatible controller" "Matrox Electronics Systems Ltd." "MGA G200e [Pilot] ServerEngines (SEP1)" -r02 "Cisco Systems Inc" "Device 0101"
0000:10:00.0 "Ethernet controller" "Intel Corporation" "I350 Gigabit Network Connection" -r01 "Cisco Systems Inc" "Device 00d6"
0000:10:00.1 "Ethernet controller" "Intel Corporation" "I350 Gigabit Network Connection" -r01 "Cisco Systems Inc" "Device 00d6"
0000:7f:08.0 "System peripheral" "Intel Corporation" "Haswell-E QPI Link 0" -r02 "Intel Corporation" "Haswell-E QPI Link 0"
"""

CONFD_CLI = """
NAME                     PHYS ADDRESS
--------------------------------------------
TenGigabitEthernet6/0/0  84:b8:02:2a:5f:c3
TenGigabitEthernet7/0/0  84:b8:02:2a:5f:c4
local0                   -
"""
CONFD_CLI_ONE_MISSING = """
NAME                     PHYS ADDRESS
--------------------------------------------
TenGigabitEthernet6/0/0  84:b8:02:2a:5f:c3
local0                   -
"""
CONFD_CLI_INVMAC = """
NAME                     PHYS ADDRESS
--------------------------------------------
TenGigabitEthernet6/0/0  no:ta:va:li:dm:ac
TenGigabitEthernet7/0/0  84:b8:02:2a:5f:c4
local0                   -
"""
CONFD_CLI_NODEVS = """
NAME                     PHYS ADDRESS
--------------------------------------------
local0                   -
"""
CONFD_CLI_NOLOCAL = """
NAME                     PHYS ADDRESS
--------------------------------------------
"""
SYS_TREE = {
    '/sys/class/net/eth2': '../../devices/pci0000:00/0000:00:1c.4/0000:10:00.0/net/eth2',
    '/sys/class/net/eth3': '../../devices/pci0000:00/0000:00:1c.4/0000:10:00.1/net/eth3',
    '/sys/class/net/juju-br0': '../../devices/virtual/net/juju-br0',
    '/sys/class/net/lo': '../../devices/virtual/net/lo',
    '/sys/class/net/lxcbr0': '../../devices/virtual/net/lxcbr0',
    '/sys/class/net/veth1GVRCF': '../../devices/virtual/net/veth1GVRCF',
    '/sys/class/net/veth7AXEUK': '../../devices/virtual/net/veth7AXEUK',
    '/sys/class/net/vethACOIJJ': '../../devices/virtual/net/vethACOIJJ',
    '/sys/class/net/vethMQ819H': '../../devices/virtual/net/vethMQ819H',
    '/sys/class/net/virbr0': '../../devices/virtual/net/virbr0',
    '/sys/class/net/virbr0-nic': '../../devices/virtual/net/virbr0-nic',
    '/sys/devices/pci0000:00/0000:00:1c.4/0000:10:00.0/net/eth2/device': '../../../0000:10:00.0',
    '/sys/devices/pci0000:00/0000:00:1c.4/0000:10:00.1/net/eth3/device': '../../../0000:10:00.1',
}
LSPCI_KS_IGB_UNBOUND = """
{} Ethernet controller: Intel Corporation I350 Gigabit Network Connection (rev 01)
        Subsystem: Cisco Systems Inc Device 00d6
"""
LSPCI_KS_IGB_BOUND = """
{} Ethernet controller: Intel Corporation I350 Gigabit Network Connection (rev 01)
        Subsystem: Cisco Systems Inc Device 00d6
        Kernel driver in use: igb
"""
LSPCI_KS_IGBUIO_BOUND = """
{} Ethernet controller: Cisco Systems Inc VIC Ethernet NIC (rev a2)
        Subsystem: Cisco Systems Inc VIC 1240 MLOM Ethernet NIC
        Kernel driver in use: igb_uio
"""
LSPCI_KS = {
    '0000:06:00.0': LSPCI_KS_IGBUIO_BOUND.format('06:00.0'),
    '0000:10:00.0': LSPCI_KS_IGB_BOUND.format('10:00.0'),
}

MODALIAS = """
alias pci:v00001137d00000071sv*sd*bc*sc*i* enic
alias pci:v00001137d00000044sv*sd*bc*sc*i* enic
alias pci:v00001137d00000043sv*sd*bc*sc*i* enic
alias pci:v00008086d000010D6sv*sd*bc*sc*i* igb
alias pci:v00008086d000010A9sv*sd*bc*sc*i* igb
alias pci:v00008086d00001522sv*sd*bc*sc*i* igb
alias pci:v00008086d00001521sv*sd*bc*sc*i* igb
alias pci:v00008086d0000157Csv*sd*bc*sc*i* igb
"""
LSPCI_NS = {
    '0000:06:00.0': "06:00.0 0200: 1137:0043 (rev a2)",
    '0000:07:00.0': "07:00.0 0200: 1137:0043 (rev a2)",
    '0000:10:00.0': "10:00.0 0200: 8086:1521 (rev 01)",
    '0000:10:00.1': "10:00.1 0200: 8086:1521 (rev 01)",
}
FILE_CONTENTS = {
    '/sys/class/net/eth2/address': 'a8:9d:21:cf:93:fc',
    '/sys/class/net/eth3/address': 'a8:9d:21:cf:93:fd',
    '/sys/class/net/eth2/operstate': 'up',
    '/sys/class/net/eth3/operstate': 'down',
    '/lib/modules/3.13.0-35-generic/modules.alias': MODALIAS,
}
COMMANDS = {
   'LSPCI_MD': ['lspci', '-m', '-D'],
   'LSPCI_KS': ['lspci', '-ks'],
   'LSPCI_NS': ['lspci', '-ns'],
   'UNAME_R': ['uname', '-r'],
   'CONFD_CLI': ['/opt/cisco/vpe/bin/confd_cli', '-N', '-C', '-u', 'system'],
}
NET_SETUP = {
    'LSPCI_MD': LSPCI,
    'UNAME_R': '3.13.0-35-generic',
    'CONFD_CLI': CONFD_CLI,
    '0000:06:00.0': {
        'LSPCI_KS': LSPCI_KS_IGBUIO_BOUND.format('06:00.0'),
        'LSPCI_NS': "06:00.0 0200: 1137:0043 (rev a2)",
    },
    '0000:07:00.0': {
        'LSPCI_KS': LSPCI_KS_IGBUIO_BOUND.format('07:00.0'),
        'LSPCI_NS': "07:00.0 0200: 1137:0043 (rev a2)",
    },
    '0000:10:00.0': {
        'LSPCI_KS': LSPCI_KS_IGB_BOUND.format('10:00.0'),
        'LSPCI_NS': "10:00.0 0200: 8086:1521 (rev 01)",
    },
    '0000:10:00.1': {
        'LSPCI_KS': LSPCI_KS_IGB_BOUND.format('10:00.1'),
        'LSPCI_NS': "10:00.1 0200: 8086:1521 (rev 01)",
    },
}
NET_SETUP_ORPHAN = copy.deepcopy(NET_SETUP)
NET_SETUP_ORPHAN['CONFD_CLI'] = CONFD_CLI_ONE_MISSING
NET_SETUP_ORPHAN['0000:07:00.0']['LSPCI_KS'] = LSPCI_KS_IGB_UNBOUND.format('07:00.0')
QN_CONF = """
lc_procs = { svm_cleanup vpe confd orca }

install_root = "/cisco"

svm_cleanup = {
        pgm = "$(install_root)/bin/svm_cleanup",
        run_once = "yes",
        max_synchronous_wait = "5.0",
        console_output = "yes"
}

vpe = { 
        pgm = "$(install_root)/bin/vpe",
        args = "unix { nodaemon log /tmp/vpe.log cli-listen localhost:5002 full-coredump } api-trace { on } dpdk { socket-mem 1024 dev 0000:00:06.0 }",
        max_cpu_percent = "111.0",
        console_output = "yes",
        crash_reset_all="yes"
}

confd = { 
        pgm = "$(install_root)/bin/confd",
        args = "--foreground -c $(install_root)/etc/confd/confd.conf",
        max_cpu_percent = "111.0",
        crash_reset_all="yes"
}

orca = { 
        pgm = "$(install_root)/bin/orca",
        args = "unix { nodaemon log /tmp/orca.log cli-listen localhost:5003 }",
        console_output = "yes",
        max_cpu_percent = "111.0",
        crash_reset_all="yes"
"""
DPKG_L = """
ii  net-tools                           1.60-25ubuntu2.1                        amd64        The NET-3 networking toolkit
ii  netbase                             5.2                                     all          Basic TCP/IP networking system
ii  netcat-openbsd                      1.105-7ubuntu1                          amd64        TCP/IP swiss army knife
ii  nova-common                         1:2014.1.4-0ubuntu2.1.1~ppa201506221720 all          OpenStack Compute - common files
"""
