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

import sys
from unittest import mock
import os

# mock out some charmhelpers libraries as they have apt install side effects
charmhelpers = mock.MagicMock()
sys.modules['charmhelpers'] = charmhelpers
sys.modules['charmhelpers.core'] = charmhelpers.core
sys.modules['charmhelpers.core.decorators'] = charmhelpers.core.decorators
sys.modules['charmhelpers.core.hookenv'] = charmhelpers.core.hookenv
sys.modules['charmhelpers.core.host'] = charmhelpers.core.host
sys.modules['charmhelpers.core.templating'] = charmhelpers.core.templating
sys.modules['charmhelpers.core.unitdata'] = charmhelpers.core.unitdata
sys.modules['charmhelpers.contrib'] = charmhelpers.contrib
sys.modules['charmhelpers.contrib.openstack'] = charmhelpers.contrib.openstack
sys.modules['charmhelpers.contrib.openstack.ha'] = (
    charmhelpers.contrib.openstack.ha)
sys.modules['charmhelpers.contrib.openstack.ip'] = (
    charmhelpers.contrib.openstack.ip)
sys.modules['charmhelpers.contrib.openstack.ha.utils'] = (
    charmhelpers.contrib.openstack.ha.utils)
sys.modules['charmhelpers.contrib.openstack.cert_utils'] = (
    charmhelpers.contrib.openstack.cert_utils)
sys.modules['charmhelpers.contrib.openstack.utils'] = (
    charmhelpers.contrib.openstack.utils)
sys.modules['charmhelpers.contrib.openstack.policyd'] = (
    charmhelpers.contrib.openstack.policyd)
sys.modules['charmhelpers.contrib.openstack.templating'] = (
    charmhelpers.contrib.openstack.templating)
sys.modules['charmhelpers.contrib.openstack.context'] = (
    charmhelpers.contrib.openstack.context)
sys.modules['charmhelpers.contrib.network'] = charmhelpers.contrib.network
sys.modules['charmhelpers.contrib.network.ip'] = (
    charmhelpers.contrib.network.ip)
sys.modules['charmhelpers.fetch'] = charmhelpers.fetch
sys.modules['charmhelpers.cli'] = charmhelpers.cli
sys.modules['charmhelpers.contrib.hahelpers'] = charmhelpers.contrib.hahelpers
sys.modules['charmhelpers.contrib.hahelpers.cluster'] = (
    charmhelpers.contrib.hahelpers.cluster)

# mock in the openstack releases so that the tests can run
# Note that these don't need to be maintained UNLESS new functionality is for
# later OpenStack releases.
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
    'caracal',
    'dalmatian',
    'epoxy',
)

# charms.reactive uses hookenv.charm_dir which must return a directory
charmhelpers.core.hookenv.charm_dir.return_value = os.path.curdir


class CompareOpenStackReleases(object):
    # This class is included due to mocking out the charmhelpers libraries
    # as they behave poorly with apt installs.

    _list = charmhelpers.contrib.openstack.utils.OPENSTACK_RELEASES

    def __init__(self, item):
        if self._list is None:
            raise Exception("Must define the _list in the class definition!")
        try:
            self.index = self._list.index(item)
        except Exception:
            raise KeyError("Item '{}' is not in list '{}'"
                           .format(item, self._list))

    def __eq__(self, other):
        assert isinstance(other, str) or isinstance(other, self.__class__)
        return self.index == self._list.index(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        assert isinstance(other, str) or isinstance(other, self.__class__)
        return self.index < self._list.index(other)

    def __ge__(self, other):
        return not self.__lt__(other)

    def __gt__(self, other):
        assert isinstance(other, str) or isinstance(other, self.__class__)
        return self.index > self._list.index(other)

    def __le__(self, other):
        return not self.__gt__(other)

    def __str__(self):
        """Always give back the item at the index so it can be used in
        comparisons like:

        s_mitaka = CompareOpenStack('mitaka')
        s_newton = CompareOpenstack('newton')

        assert s_newton > s_mitaka

        @returns: <string>
        """
        return self._list[self.index]


charmhelpers.contrib.openstack.utils.CompareOpenStackReleases = \
    CompareOpenStackReleases


def _fake_retry(num_retries, base_delay=0, exc_type=Exception):
    def _retry_on_exception_inner_1(f):
        def _retry_on_exception_inner_2(*args, **kwargs):
            return f(*args, **kwargs)
        return _retry_on_exception_inner_2
    return _retry_on_exception_inner_1


mock.patch(
    'charmhelpers.core.decorators.retry_on_exception',
    _fake_retry).start()


def _fake_cached(f):
    return f


mock.patch(
    'charmhelpers.core.hookenv.cached',
    _fake_cached).start()
