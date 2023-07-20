import sys
from unittest import mock

charmhelpers = None


def mock_charmhelpers():
    # Mock out charmhelpers so that we can test without it.
    # also stops sideeffects from occuring.
    global charmhelpers
    charmhelpers = mock.MagicMock()
    sys.modules['charmhelpers'] = charmhelpers
    sys.modules['charmhelpers.core'] = charmhelpers.core
    sys.modules['charmhelpers.core.hookenv'] = charmhelpers.core.hookenv
    sys.modules['charmhelpers.core.host'] = charmhelpers.core.host
    sys.modules['charmhelpers.core.unitdata'] = charmhelpers.core.unitdata
    sys.modules['charmhelpers.core.templating'] = charmhelpers.core.templating
    sys.modules['charmhelpers.contrib'] = charmhelpers.contrib
    sys.modules['charmhelpers.contrib.openstack'] = (
        charmhelpers.contrib.openstack)
    sys.modules['charmhelpers.contrib.openstack.context'] = (
        charmhelpers.contrib.openstack.context)
    sys.modules['charmhelpers.contrib.openstack.ha'] = (
        charmhelpers.contrib.openstack.ha)
    sys.modules['charmhelpers.contrib.openstack.ha.utils'] = (
        charmhelpers.contrib.openstack.ha.utils)
    sys.modules['charmhelpers.contrib.openstack.ip'] = (
        charmhelpers.contrib.openstack.ip)
    sys.modules['charmhelpers.contrib.openstack.utils'] = (
        charmhelpers.contrib.openstack.utils)
    sys.modules['charmhelpers.contrib.openstack.cert_utils'] = (
        charmhelpers.contrib.openstack.cert_utils)
    sys.modules['charmhelpers.contrib.openstack.templating'] = (
        charmhelpers.contrib.openstack.templating)
    sys.modules['charmhelpers.contrib.openstack.policyd'] = (
        charmhelpers.contrib.openstack.policyd)
    sys.modules['charmhelpers.contrib.storage'] = (
        charmhelpers.contrib.storage)
    sys.modules['charmhelpers.contrib.storage.linux'] = (
        charmhelpers.contrib.storage.linux)
    sys.modules['charmhelpers.contrib.storage.linux.ceph'] = (
        charmhelpers.contrib.storage.linux.ceph)
    sys.modules['charmhelpers.contrib.network'] = charmhelpers.contrib.network
    sys.modules['charmhelpers.contrib.network.ip'] = (
        charmhelpers.contrib.network.ip)
    sys.modules['charmhelpers.contrib.charmsupport'] = (
        charmhelpers.contrib.charmsupport)
    sys.modules['charmhelpers.fetch'] = charmhelpers.fetch
    sys.modules['charmhelpers.cli'] = charmhelpers.cli
    sys.modules['charmhelpers.contrib.hahelpers'] = (
        charmhelpers.contrib.hahelpers)
    sys.modules['charmhelpers.contrib.hahelpers.cluster'] = (
        charmhelpers.contrib.hahelpers.cluster)
    sys.modules['charmhelpers.core.hookenv.charm_dir'] = (
        charmhelpers.core.hookenv.charm_dir)
    charmhelpers.core.hookenv.charm_dir.return_value = "/tmp"

    # mock in the openstack releases so that the tests can run
    charmhelpers.contrib.openstack.utils.OPENSTACK_RELEASES = (
        'diablo',
        'essex',
        'folsom',
        'grizzly',
        'havana',
        'icehouse',
        'juno',
        'kilo',
        'liberty',
        'mitaka',
        'newton',
        'ocata',
        'pike',
        'queens',
        'rocky',
        'stein',
        'train',
        'ussuri',
        'victoria',
        'wallaby',
        'xena',
        'yoga',
        'zed',
        'antelope',
        'bobcat',
    )
