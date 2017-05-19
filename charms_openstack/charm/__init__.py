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

# OpenStackCharm() - base class for build OpenStack charms from for the
# reactive framework.

# Pull in helpers that 'charms_openstack.charm' will export
from charms_openstack.charm.defaults import use_defaults
from charms_openstack.charm.core import (
    optional_interfaces,
    provide_charm_instance,
    get_charm_instance,
    register_os_release_selector,
)
from charms_openstack.charm.classes import (
    OpenStackCharm,
    OpenStackAPICharm,
    HAOpenStackCharm,
)

__all__ = (
    "OpenStackCharm",
    "OpenStackAPICharm",
    "HAOpenStackCharm",
    "optional_interfaces",
    "provide_charm_instance",
    "get_charm_instance",
    "register_os_release_selector",
    "use_defaults",
)
