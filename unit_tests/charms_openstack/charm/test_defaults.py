import collections
import mock

import charms_openstack.charm.core as chm_core
import charms_openstack.charm.defaults as chm

from unit_tests.charms_openstack.charm.utils import BaseOpenStackCharmTest

TEST_CONFIG = {'config': True}


class TestDefaults(BaseOpenStackCharmTest):

    def setUp(self):
        super().setUp(chm_core.BaseOpenStackCharm, TEST_CONFIG)

    def test_use_defaults(self):
        self.patch_object(chm, 'ALLOWED_DEFAULT_HANDLERS', new=['handler'])
        self.patch_object(chm, '_default_handler_map', new={})
        # first check for a missing handler.
        with self.assertRaises(RuntimeError):
            chm.use_defaults('does not exist')
        # now check for an allowed handler, but no function.
        with self.assertRaises(RuntimeError):
            chm.use_defaults('handler')

        class TestException(Exception):
            pass

        # finally, have an actual handler.
        @chm._map_default_handler('handler')
        def do_handler():
            raise TestException()

        with self.assertRaises(TestException):
            chm.use_defaults('handler')

    def test_map_default_handler(self):
        self.patch_object(chm, 'ALLOWED_DEFAULT_HANDLERS', new=['handler'])
        self.patch_object(chm, '_default_handler_map', new={})
        # test that we can only map allowed handlers.
        with self.assertRaises(RuntimeError):
            @chm._map_default_handler('does-not-exist')
            def test_func1():
                pass

        # test we can only map a handler once
        @chm._map_default_handler('handler')
        def test_func2():
            pass

        with self.assertRaises(RuntimeError):
            @chm._map_default_handler('handler')
            def test_func3():
                pass

    @staticmethod
    def mock_decorator_gen():
        _map = {}

        def mock_generator(state):
            def wrapper(f):
                _map[state] = f

                def wrapped(*args, **kwargs):
                    return f(*args, **kwargs)
                return wrapped
            return wrapper

        Handler = collections.namedtuple('Handler', ['map', 'decorator'])
        return Handler(_map, mock_generator)

    @staticmethod
    def mock_decorator_gen_simple():
        _func = {}

        def wrapper(f):
            _func['function'] = f

            def wrapped(*args, **kwargs):
                return f(*args, **kwargs)
            return wrapped

        Handler = collections.namedtuple('Handler', ['map', 'decorator'])
        return Handler(_func, wrapper)

    def test_default_install_handler(self):
        self.assertIn('charm.installed', chm._default_handler_map)
        self.patch_object(chm.reactive, 'set_state')
        f = chm._default_handler_map['charm.installed']
        f()
        self.set_state.assert_called_once_with(
            'charms.openstack.do-default-charm.installed')

    def test_default_select_release_handler(self):
        self.assertIn('charm.default-select-release', chm._default_handler_map)
        self.patch_object(chm, 'register_os_release_selector')
        h = self.mock_decorator_gen_simple()
        self.register_os_release_selector.side_effect = h.decorator
        # call the default handler installer function, and check its map.
        f = chm._default_handler_map['charm.default-select-release']
        f()
        self.assertIsNotNone(h.map['function'])
        # verify that the installed function works
        kv = mock.MagicMock()
        self.patch_object(chm.unitdata, 'kv', new=lambda: kv)
        self.patch_object(chm.os_utils, 'os_release')
        # set a release
        kv.get.return_value = 'one'
        release = h.map['function']()
        self.assertEqual(release, 'one')
        kv.set.assert_not_called()
        kv.get.assert_called_once_with(chm.OPENSTACK_RELEASE_KEY, None)
        # No release set, ensure it calls os_release
        kv.reset_mock()
        kv.get.return_value = None
        self.os_release.return_value = 'two'
        release = h.map['function']()
        self.assertEqual(release, 'two')
        kv.set.assert_called_once_with(chm.OPENSTACK_RELEASE_KEY, 'two')
        self.os_release.assert_called_once_with('python-keystonemiddleware')

    def test_default_select_package_type_handler(self):
        self.assertIn('charm.default-select-package-type',
                      chm._default_handler_map)
        self.patch_object(chm, 'register_package_type_selector')
        h = self.mock_decorator_gen_simple()
        self.register_package_type_selector.side_effect = h.decorator
        # call the default handler installer function, and check its map.
        f = chm._default_handler_map['charm.default-select-package-type']
        f()
        self.assertIsNotNone(h.map['function'])
        # verify that the installed function works
        kv = mock.MagicMock()
        self.patch_object(chm.unitdata, 'kv', new=lambda: kv)
        self.patch_object(chm.os_utils, 'snap_install_requested',
                          return_value=False)
        # set a package_type
        kv.get.return_value = 'deb'
        package_type = h.map['function']()
        self.assertEqual(package_type, 'deb')
        kv.set.assert_not_called()
        kv.get.assert_called_once_with(chm.OPENSTACK_PACKAGE_TYPE_KEY, None)

        # No release set, ensure it calls snap_install_requested and
        # sets package_type to 'snap'
        kv.reset_mock()
        kv.get.return_value = None
        self.snap_install_requested.return_value = True
        package_type = h.map['function']()
        self.assertEqual(package_type, 'snap')
        kv.set.assert_called_once_with(chm.OPENSTACK_PACKAGE_TYPE_KEY, 'snap')
        self.snap_install_requested.assert_called_once_with()

        # No release set, ensure it calls snap_install_requested and
        # sets package_type to 'deb'
        kv.reset_mock()
        kv.get.return_value = None
        self.snap_install_requested.reset_mock()
        self.snap_install_requested.return_value = False
        package_type = h.map['function']()
        self.assertEqual(package_type, 'deb')
        kv.set.assert_called_once_with(chm.OPENSTACK_PACKAGE_TYPE_KEY, 'deb')
        self.snap_install_requested.assert_called_once_with()

    def test_default_amqp_connection_handler(self):
        self.assertIn('amqp.connected', chm._default_handler_map)
        self.patch_object(chm.reactive, 'set_state')
        # call the default handler installer function, and check its map.
        f = chm._default_handler_map['amqp.connected']
        f()
        self.set_state.assert_called_once_with(
            'charms.openstack.do-default-amqp.connected')

    def test_default_setup_datatbase_handler(self):
        self.assertIn('shared-db.connected', chm._default_handler_map)
        self.patch_object(chm.reactive, 'set_state')
        # call the default handler installer function, and check its map.
        f = chm._default_handler_map['shared-db.connected']
        f()
        self.set_state.assert_called_once_with(
            'charms.openstack.do-default-shared-db.connected')

    def test_default_setup_endpoint_handler(self):
        self.assertIn('identity-service.connected', chm._default_handler_map)
        self.patch_object(chm.reactive, 'set_state')
        f = chm._default_handler_map['identity-service.connected']
        f()
        self.set_state.assert_called_once_with(
            'charms.openstack.do-default-identity-service.connected')

    def test_default_setup_endpoint_available_handler(self):
        self.assertIn('identity-service.available', chm._default_handler_map)
        self.patch_object(chm.reactive, 'set_state')
        # call the default handler installer function, and check its map.
        f = chm._default_handler_map['identity-service.available']
        f()
        self.set_state.assert_called_once_with(
            'charms.openstack.do-default-identity-service.available')

    def test_default_config_changed_handler(self):
        self.assertIn('config.changed', chm._default_handler_map)
        self.patch_object(chm.reactive, 'set_state')
        f = chm._default_handler_map['config.changed']
        f()
        self.set_state.assert_called_once_with(
            'charms.openstack.do-default-config.changed')

    def test_default_update_status_handler(self):
        self.assertIn('update-status', chm._default_handler_map)
        self.patch_object(chm.reactive, 'set_state')
        f = chm._default_handler_map['update-status']
        f()
        self.set_state.assert_called_once_with(
            'charms.openstack.do-default-update-status')

    def test_default_upgrade_charm_handler(self):
        self.assertIn('upgrade-charm', chm._default_handler_map)
        self.patch_object(chm.reactive, 'set_state')
        f = chm._default_handler_map['upgrade-charm']
        f()
        self.set_state.assert_called_once_with(
            'charms.openstack.do-default-upgrade-charm')

    def test_default_render_configs(self):
        self.patch_object(chm, 'OpenStackCharm', name='charm')
        interfaces = ['a', 'b', 'c']
        chm.default_render_configs(*interfaces)
        self.charm.singleton.render_configs.assert_called_once_with(
            tuple(interfaces))
        self.charm.singleton.assess_status.assert_called_once_with()
