import collections

import charms_openstack.charm.core as chm_core
import charms_openstack.charm.classes as chm_classes

# Helper class to make testing the charms possible


class MyAdapter(object):

    def __init__(self, interfaces, charm_instance=None):
        self.interfaces = interfaces


# force the series to just contain my-series.
# NOTE that this is mocked out in the __init__.py for the unit_tests package
chm_core.os_utils.OPENSTACK_CODENAMES = collections.OrderedDict([
    ('2011.2', 'my-series'),
])


class MyOpenStackCharm(chm_classes.OpenStackCharm):

    release = 'icehouse'
    name = 'my-charm'
    packages = ['p1', 'p2', 'p3', 'package-to-filter']
    snaps = ['mysnap']
    version_package = 'p2'
    version_snap = 'mysnap'
    api_ports = {
        'service1': {
            'public': 1,
            'int': 2,
        },
        'service2': {
            'public': 3,
        },
        'my-default-service': {
            'public': 1234,
            'admin': 2468,
            'int': 3579,
        },
    }
    service_type = 'my-service-type'
    default_service = 'my-default-service'
    restart_map = {
        'path1': ['s1'],
        'path2': ['s2'],
        'path3': ['s3'],
        'path4': ['s2', 's4'],
    }
    required_relations = []
    sync_cmd = ['my-sync-cmd', 'param1']
    services = ['my-default-service', 'my-second-service']
    adapters_class = MyAdapter
    release_pkg = 'my-pkg'


class MyNextOpenStackCharm(MyOpenStackCharm):

    release = 'mitaka'
