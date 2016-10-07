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

import itertools
import mock
import unittest

import charmhelpers.core.unitdata as unitdata


class PatchHelper(unittest.TestCase):
    """Helper Test Class based on unittest.TestCase which provides an easy way
    to patch object for a test without using a decorator and then clean them up
    afterwards
    """

    def setUp(self):
        self._patches = {}
        self._patches_start = {}

    def tearDown(self):
        for k, v in self._patches.items():
            v.stop()
            setattr(self, k, None)
        self._patches = None
        self._patches_start = None

    def patch(self, patchee, name=None, **kwargs):
        """Patch a patchable thing.  Uses mock.patch() to do the work.
        Automatically unpatches at the end of the test.

        The mock gets added to the test object (self) using 'name' or the last
        part of the patchee string, after the final dot.

        :param patchee: <string> representing module.object that is to be
            patched.
        :param name: optional <string> name to call the mock.
        :param **kwargs: any other args to pass to mock.patch()
        """
        mocked = mock.patch(patchee, **kwargs)
        if name is None:
            name = patchee.split('.')[-1]
        started = mocked.start()
        self._patches[name] = mocked
        self._patches_start[name] = started
        setattr(self, name, started)

    def patch_object(self, obj, attr, name=None, **kwargs):
        """Patch a patchable thing.  Uses mock.patch.object() to do the work.
        Automatically unpatches at the end of the test.

        The mock gets added to the test object (self) using 'name' or the attr
        passed in the arguments.

        :param obj: an object that needs to have an attribute patched.
        :param attr: <string> that represents the attribute being patched.
        :param name: optional <string> name to call the mock.
        :param **kwargs: any other args to pass to mock.patch()
        """
        mocked = mock.patch.object(obj, attr, **kwargs)
        if name is None:
            name = attr
        started = mocked.start()
        self._patches[name] = mocked
        self._patches_start[name] = started
        setattr(self, attr, started)

    def patch_release(self, release):
        """Patch the unitdata.kv.get() function to always return the release

        This is to just bake in a particular release for testing.

        Note that this relies on self being an instance of a test class
        derived from PatchHelper()

        :param release: <string> of the release to always return
        """
        _getter = mock.MagicMock()
        _getter.get.return_value = release
        self.patch_object(unitdata, 'kv')
        self.kv.return_value = _getter


class TestRegisteredHooks(PatchHelper):
    # Testing helpers for @when, @when_not, @hook, etc. hooks on a module
    # relies on reloading the module to get the effect wanted.

    _hooks = {}
    HOOK_TYPES = ['when', 'when_not', 'hook', 'not_unless', 'only_once',
                  'when_all', 'when_any', 'when_file_changed', 'when_none',
                  'when_not_all']
    _module = None

    # These defaults are for the default settings and are searched for if the
    # user is using defaults.
    DEFAULTS = {
        'when': {
            'default_amqp_connection': ('amqp.connected', ),
            'default_setup_database': ('shared-db.connected', ),
            'default_setup_endpoint_connection': (
                'identity-service.connected', ),
            'default_config_changed': ('config.changed', ),
            'default_setup_endpoint_available': (
                'identity-service.available', ),
        },
        'when_not': {
            'default_install': ('charm.installed', ),
        },
        'hook': {
            'default_update_status': ('update-status', ),
        },
    }

    @staticmethod
    def mock_hook_factory(d):

        def mock_hook(*args, **kwargs):

            def inner(f):
                # remember what we were passed.  Note that we can't actually
                # determine the class we're attached to, as the decorator only
                # gets the function.
                try:
                    d[f.__name__].append(dict(args=args, kwargs=kwargs))
                except KeyError:
                    d[f.__name__] = [dict(args=args, kwargs=kwargs)]
                return f
            return inner
        return mock_hook

    def _mock_hook(self, hook):
        """Mock out a hook in charms.reactive

        :param hook: <string> name of hook to patch out.
        """
        if hook not in self.HOOK_TYPES:
            raise KeyError("Hook '{}' is not a reactive hook".format(hook))
        self._hooks[hook] = {}
        self.patch("charms.reactive.{hook}".format(hook=hook),
                   new=self.mock_hook_factory(self._hooks[hook]),
                   name='patched_{hook}'.format(hook=hook))

    @classmethod
    def tearDownClass(cls):
        # and fix any breakage we did to the module
        if cls._module:
            try:
                reload(cls._module)
            except NameError:
                import importlib
                importlib.reload(cls._module)

    def registered_hooks_test_helper(self, module, hook_set, defaults=None):
        """Note this isn't a test that is called by unittest.  It is for a test
        to call to test the registered hooks

        The hook_set maps hooks -> function_names -> lists of states. e.g.

        {
            'when': {
                'function_name': ('state1', 'state2', ...),
            }
        }

        :param module: the module to reload to get it to run the hooks
        :param hook_set: a specification of what function names map to which
            hooks -- see above
        :param defaults: a list of strings for defaults used that the charm
            author wants to check actually are set.
        """
        defaults = defaults or []
        # extract the name of the hook from default states.
        default_hooks = set(
            hook for hook, spec in self.DEFAULTS.items()
            if (set(defaults).intersection(itertools.chain(*spec.values()))))
        # set up the hooks for the passed ones and any defaults
        for hook in default_hooks.union(hook_set.keys()):
            self._mock_hook(hook)

        self.__class__._module = module

        # force requires to rerun the mock_hook decorator:
        # try except is Python2/Python3 compatibility as Python3 has moved
        # reload to importlib.
        try:
            reload(module)
        except NameError:
            import importlib
            importlib.reload(module)

        # merge the default hooks and hook_set's to find a set of functions
        # that should exist.
        test_set = hook_set.copy()
        set_defaults = set(defaults)
        for default_hook, spec in self.DEFAULTS.items():
            for f, state_list in spec.items():
                if set_defaults.intersection(state_list):
                    try:
                        test_set[default_hook][f] = state_list
                    except KeyError:
                        test_set[default_hook] = {}
                        test_set[default_hook][f] = state_list

        # test that the hooks actually registered the relation expressions that
        # are meaningful for this interface: this is to handle regressions.
        # The keys are the function names that the hook attaches to.
        # self._hook['when'] is for when the (f, {args}) are captured.
        for t, p in ((self._hooks[hook], patterns)
                     for hook, patterns in test_set.items()):
            for f, args in t.items():
                # check that function is in patterns
                self.assertIn(f, p.keys())
                # check that the lists are equal
                l = [a['args'][0] for a in args]
                self.assertEqual(l, sorted(p[f]))
