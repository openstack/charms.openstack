import mock

import unit_tests.utils

import charms_openstack.charm.core as chm_core


class BaseOpenStackCharmTest(unit_tests.utils.BaseTestCase):

    @classmethod
    def setUpClass(cls):
        cls.patched_config = mock.patch.object(chm_core.hookenv, 'config')
        cls.patched_config_started = cls.patched_config.start()

    @classmethod
    def tearDownClass(cls):
        cls.patched_config.stop()
        cls.patched_config_started = None
        cls.patched_config = None

    def _get_config(self, x=None):
        if x:
            return self._test_config.get(x, None)
        else:
            return self._test_config

    def setUp(self, target_cls, test_config):
        super().setUp()
        # set up the return value on the mock before instantiating the class to
        # get the config into the class.config.
        self._test_config = test_config
        chm_core.hookenv.config.side_effect = self._get_config
        self.target = target_cls()

    def tearDown(self):
        self.target = None
        # if we've created a singleton on the module, also destroy that.
        chm_core._singleton = None
        super().tearDown()

    def patch_target(self, attr, return_value=None, name=None, new=None,
                     **kwargs):
        # uses BaseTestCase.patch_object() to patch targer.
        self.patch_object(self.target, attr, return_value, name, new, **kwargs)


class TestConfig(object):

    def __init__(self):
        self.config = {}
        self.config_prev = {}

    def __call__(self, key=None):
        if key:
            return self.get(key)
        else:
            return self

    def previous(self, k):
        return self.config_prev[k] if k in self.config_prev else self.config[k]

    def set_previous(self, k, v):
        self.config_prev[k] = v

    def unset_previous(self, k):
        if k in self.config_prev:
            self.config_prev.pop(k)

    def changed(self, k):
        if not self.config_prev:
            return True
        return self.get(k) != self.previous(k)

    def get(self, attr=None):
        if not attr:
            return self
        try:
            return self.config[attr]
        except KeyError:
            return None

    def get_all(self):
        return self.config

    def set(self, attr, value):
        self.config[attr] = value

    def __getitem__(self, k):
        return self.get(k)
