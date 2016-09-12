import subprocess

import charmhelpers.core.hookenv as hookenv


def set_manager(connection_url):
    """Configure the OVSDB manager for the switch

    :param connection_url: str URL for OVS manager
    """
    subprocess.check_call(['ovs-vsctl', 'set-manager', connection_url])


@hookenv.cached
def _get_ovstbl():
    ovstbl = subprocess.check_output(['ovs-vsctl', 'get',
                                      'Open_vSwitch', '.',
                                      '_uuid']).strip()
    return ovstbl


def set_config(key, value, table='other_config'):
    """Set key value pairs in a table

    :param key: str
    :param value: str
    :param table: str Table to apply setting to
    """
    subprocess.check_call(
        ['ovs-vsctl', 'set',
         'Open_vSwitch', _get_ovstbl(),
         '{}:{}={}'.format(table, key, value)]
    )
