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

# Note that the unit_tests/__init__.py has the following lines to stop
# side effects from the imorts from charm helpers.

# mock out some charmhelpers libraries as they have apt install side effects
# sys.modules['charmhelpers.contrib.openstack.utils'] = mock.MagicMock()
# sys.modules['charmhelpers.contrib.network.ip'] = mock.MagicMock()

import unittest

import charms.reactive

import charms_openstack.test_utils as test_utils


class TestPatchHelper(unittest.TestCase):

    static_thing = None

    def test_patch(self):

        class ClassUnderTest(test_utils.PatchHelper):

            def a_method(self):
                self.value = TestPatchHelper.static_thing

            # for py27 we have to convince unittest this is okay
            def runTest(self):
                pass

        thing = ClassUnderTest()
        thing.setUp()
        self.assertEqual(thing._patches, {})
        self.assertEqual(thing._patches_start, {})
        thing.patch('unit_tests.test_charms_openstack_test_utils.'
                    'TestPatchHelper.static_thing',
                    name='a', new=5)
        self.assertIn('a', thing._patches)
        self.assertIn('a', thing._patches_start)
        self.assertEqual(thing.a, 5)
        self.assertEqual(self.static_thing, 5)
        thing.a_method()
        thing.tearDown()
        self.assertEqual(thing._patches, None)
        self.assertEqual(thing._patches_start, None)
        self.assertEqual(self.static_thing, None)
        self.assertEqual(thing.value, 5)

    def test_patch_object(self):

        class ClassUnderTest(test_utils.PatchHelper):

            def a_method(self):
                self.value = TestPatchHelper.static_thing

            # for py27 we have to convince unittest this is okay
            def runTest(self):
                pass

        thing = ClassUnderTest()
        thing.setUp()
        thing.patch_object(TestPatchHelper, 'static_thing',
                           name='a', new=10)
        self.assertEqual(thing.a, 10)
        self.assertEqual(self.static_thing, 10)
        thing.a_method()
        thing.tearDown()
        self.assertEqual(thing.value, 10)

    def test_patch_release(self):

        import charmhelpers.core.unitdata as unitdata

        class ClassUnderTest(test_utils.PatchHelper):

            # for py27 we have to convince unittest this is okay
            def runTest(self):
                pass

        thing = ClassUnderTest()
        thing.setUp()
        thing.patch_release('bugs-bunny')
        self.assertEqual(unitdata.kv().get(), 'bugs-bunny')
        thing.tearDown()


# These functions are to help with testing the mocking hooks.
@charms.reactive.when('when_state1')
def func1(state1):
    pass


@charms.reactive.when_not('when_not_state1')
@charms.reactive.when_not('when_not_state2')
def func2():
    pass


@charms.reactive.hook('hook_state1', 'hook_state3')
@charms.reactive.hook('hook_state2')
def func3():
    pass


class TestTestRegisteredHooks(test_utils.TestRegisteredHooks):

    def test_hooks(self):
        defaults = [
            'charm.installed',
        ]
        hook_set = {
            'when': {
                'func1': ('when_state1', ),
            },
            'when_not': {
                'func2': ('when_not_state1', 'when_not_state2'),
            },
            'hook': {
                'func3': ('hook_state1', 'hook_state2', 'hook_state3', ),
            },
        }
        # test that the hooks were registered via the
        # reactive.barbican_handlers
        import sys
        handlers = sys.modules[__name__]
        self.registered_hooks_test_helper(handlers, hook_set, defaults)
