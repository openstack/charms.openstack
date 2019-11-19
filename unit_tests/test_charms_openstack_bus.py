# Copyright 2014-2018 Canonical Limited.
#
# This file is part of charms.reactive.
#
# charms.reactive is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3 as
# published by the Free Software Foundation.
#
# charm-helpers is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with charm-helpers.  If not, see <http://www.gnu.org/licenses/>.

import os
import unittest

import mock

import charms_openstack.bus as bus


class TestBus(unittest.TestCase):

    @mock.patch.object(bus.os, 'walk')
    @mock.patch.object(bus, '_register_handlers_from_file')
    @mock.patch('charmhelpers.core.hookenv.charm_dir')
    def test_discover(self, charm_dir, _register_handlers_from_file, walk):
        os.walk.return_value = [(
            '/x/unit-aodh-1/charm/lib/charm/openstack',
            ['__pycache__'],
            ['__init__.py', 'aodh.py'])]

        charm_dir.return_value = '/x/unit-aodh-1/charm'
        bus.discover()
        expect_calls = [
            mock.call(
                '/x/unit-aodh-1/charm/lib/charm',
                '/x/unit-aodh-1/charm/lib/charm/openstack/__init__.py'),
            mock.call(
                '/x/unit-aodh-1/charm/lib/charm',
                '/x/unit-aodh-1/charm/lib/charm/openstack/aodh.py')]
        _register_handlers_from_file.assert_has_calls(expect_calls)

    @mock.patch.object(bus.os, 'walk')
    @mock.patch.object(bus, '_register_handlers_from_file')
    @mock.patch('charmhelpers.core.hookenv.charm_dir')
    def test_discover_search_path(self, charm_dir,
                                  _register_handlers_from_file, walk):
        os.walk.return_value = [(
            '/x/unit-aodh-1/charm/lib/charms',
            ['__pycache__'],
            ['__init__.py', 'aodh.py'])]

        bus.discover(search_path='/x/unit-aodh-1/charm/lib/charms')
        expect_calls = [
            mock.call(
                '/x/unit-aodh-1/charm/lib',
                '/x/unit-aodh-1/charm/lib/charms/__init__.py'),
            mock.call(
                '/x/unit-aodh-1/charm/lib',
                '/x/unit-aodh-1/charm/lib/charms/aodh.py')]
        _register_handlers_from_file.assert_has_calls(expect_calls)

    @mock.patch.object(bus.importlib, 'import_module')
    def test_load_module(self, import_module):
        import_module.side_effect = lambda x: x
        bus._load_module(
            '/x/charm/lib/charm',
            '/x/charm/lib/charm/openstack/aodh.py'),
        import_module.assert_called_once_with('charm.openstack.aodh')

    @mock.patch.object(bus, '_load_module')
    def test_register_handlers_from_file(self, _load_module):
        bus._register_handlers_from_file('reactive', 'reactive/foo.py')
        _load_module.assert_called_once_with('reactive', 'reactive/foo.py')
