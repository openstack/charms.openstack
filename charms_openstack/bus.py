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

import importlib
import os
import charmhelpers.core.hookenv as hookenv

# Code below is based on charms.reactive.bus


def discover():
    """Discover Openstack handlers based on convention.

    Handlers will be loaded from the following directory and its
    subdirectories:

      * ``$CHARM_DIR/lib/charm/openstack``

    The Python files will be imported and decorated functions registered.
    """
    search_path = os.path.join(
        hookenv.charm_dir(), 'lib', 'charm', 'openstack')
    base_path = os.path.join(hookenv.charm_dir(), 'lib', 'charm')
    for dirpath, dirnames, filenames in os.walk(search_path):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            _register_handlers_from_file(base_path, filepath)


def _load_module(root, filepath):
    """Import the supplied module.

    :param root: Module root directory eg directory that the import is
                 relative to.
    :type root: str
    :param filepath: Module file.
    :type filepath: str
    """
    assert filepath.startswith(root + os.sep)
    assert filepath.endswith('.py')
    package = os.path.basename(root)
    module = filepath[len(root):-3].replace(os.sep, '.')
    if module.endswith('.__init__'):
        module = module[:-9]

    # Standard import.
    importlib.import_module(package + module)


def _register_handlers_from_file(root, filepath):
    """Import the supplied module if its a good candidate.

    :param root: Module root directory eg directory that the import is
                 relative to.
    :type root: str
    :param filepath: Module file.
    :type filepath: str
    """
    no_exec_blacklist = (
        '.md', '.yaml', '.txt', '.ini',
        'makefile', '.gitignore',
        'copyright', 'license')
    if filepath.lower().endswith(no_exec_blacklist):
        # Don't load handlers with one of the blacklisted extensions
        return
    if filepath.endswith('.py'):
        _load_module(root, filepath)
