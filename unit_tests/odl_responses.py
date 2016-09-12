NEUTRON_NET_MAP = """
{
  "neutron_net_map": {
    "physicalNetwork": [
      {
        "name": "net_d12",
        "device": [
          {
            "device-name": "C240-M4-6",
            "device-type": "vhostuser",
            "interface": [
              {
                "interface-name": "TenGigabitEthernet6/0/0",
                "macAddress": "84:b8:02:2a:5f:c3"
              }
            ]
          }
        ]
      },
      {
        "name": "net_d11",
        "device": [
          {
            "device-name": "C240-M4-6",
            "device-type": "vhostuser",
            "interface": [
              {
                "interface-name": "TenGigabitEthernet7/0/0",
                "macAddress": "84:b8:02:2a:5f:c4"
              }
            ]
          }
        ]
      },
      {
        "name": "net_d10",
        "device": [
          {
            "device-name": "C240-M4-6",
            "device-type": "vhostuser",
            "interface": [
              {
                "interface-name": "TenGigabitEthernet6/0/0",
                "macAddress": "84:b8:02:2a:5f:c3"
              }
            ]
          }
        ]
      }
    ]
  }
}"""

NEUTRON_NET_MAP_EMPTY = """
{
  "neutron_net_map": {
    "physicalNetwork": [
    ]
  }
}"""

ODL_REGISTERED_NODES = """
{
  "nodes": {
    "node": [
      {
        "id": "C240-M4-6"
      },
      {
        "id": "controller-config"
      }
    ]
  }
}"""
