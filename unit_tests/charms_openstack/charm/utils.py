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

    def setUp(self, target_cls, test_config):
        super().setUp()
        # set up the return value on the mock before instantiating the class to
        # get the config into the class.config.
        chm_core.hookenv.config.return_value = test_config
        self.target = target_cls()

    def tearDown(self):
        self.target = None
        # if we've created a singleton on the module, also destroy that.
        chm_core._singleton = None
        super().tearDown()

    def patch_target(self, attr, return_value=None, name=None, new=None):
        # uses BaseTestCase.patch_object() to patch targer.
        self.patch_object(self.target, attr, return_value, name, new)
