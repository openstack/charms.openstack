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
import mock

# mock out some charmhelpers libraries as they have apt install side effects
apt_pkg = mock.MagicMock()
charmhelpers = mock.MagicMock()
sys.modules['apt_pkg'] = apt_pkg
sys.modules['charmhelpers'] = charmhelpers
sys.modules['charmhelpers.core'] = charmhelpers.core
sys.modules['charmhelpers.core.hookenv'] = charmhelpers.core.hookenv
sys.modules['charmhelpers.core.host'] = charmhelpers.core.host
sys.modules['charmhelpers.core.templating'] = charmhelpers.core.templating
sys.modules['charmhelpers.core.unitdata'] = charmhelpers.core.unitdata
sys.modules['charmhelpers.contrib'] = charmhelpers.contrib
sys.modules['charmhelpers.contrib.openstack'] = charmhelpers.contrib.openstack
sys.modules['charmhelpers.contrib.openstack.utils'] = (
    charmhelpers.contrib.openstack.utils)
sys.modules['charmhelpers.contrib.openstack.templating'] = (
    charmhelpers.contrib.openstack.templating)
sys.modules['charmhelpers.contrib.network'] = charmhelpers.contrib.network
sys.modules['charmhelpers.contrib.network.ip'] = (
    charmhelpers.contrib.network.ip)
sys.modules['charmhelpers.fetch'] = charmhelpers.fetch
sys.modules['charmhelpers.cli'] = charmhelpers.cli
sys.modules['charmhelpers.contrib.hahelpers'] = charmhelpers.contrib.hahelpers
sys.modules['charmhelpers.contrib.hahelpers.cluster'] = (
    charmhelpers.contrib.hahelpers.cluster)
