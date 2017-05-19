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
        self.patch_object(chm.reactive, 'when_not')
        h = self.mock_decorator_gen()
        self.when_not.side_effect = h.decorator
        # call the default handler installer function, and check its map.
        f = chm._default_handler_map['charm.installed']
        f()
        self.assertIn('charm.installed', h.map)
        # verify that the installed function calls the charm installer
        self.patch_object(chm, 'OpenStackCharm', name='charm')
        kv = mock.MagicMock()
        self.patch_object(chm.unitdata, 'kv', new=lambda: kv)
        self.patch_object(chm.reactive, 'set_state')
        h.map['charm.installed']()
        kv.unset.assert_called_once_with(chm.OPENSTACK_RELEASE_KEY)
        self.charm.singleton.install.assert_called_once_with()
        self.set_state.assert_called_once_with('charm.installed')

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

    def test_default_amqp_connection_handler(self):
        self.assertIn('amqp.connected', chm._default_handler_map)
        self.patch_object(chm.reactive, 'when')
        h = self.mock_decorator_gen()
        self.when.side_effect = h.decorator
        # call the default handler installer function, and check its map.
        f = chm._default_handler_map['amqp.connected']
        f()
        self.assertIn('amqp.connected', h.map)
        # verify that the installed function works
        self.patch_object(chm, 'OpenStackCharm', name='charm')
        self.charm.singleton.get_amqp_credentials.return_value = \
            ('user', 'vhost')
        amqp = mock.MagicMock()
        h.map['amqp.connected'](amqp)
        self.charm.singleton.get_amqp_credentials.assert_called_once_with()
        amqp.request_access.assert_called_once_with(username='user',
                                                    vhost='vhost')
        self.charm.singleton.assess_status.assert_called_once_with()

    def test_default_setup_datatbase_handler(self):
        self.assertIn('shared-db.connected', chm._default_handler_map)
        self.patch_object(chm.reactive, 'when')
        h = self.mock_decorator_gen()
        self.when.side_effect = h.decorator
        # call the default handler installer function, and check its map.
        f = chm._default_handler_map['shared-db.connected']
        f()
        self.assertIn('shared-db.connected', h.map)
        # verify that the installed function works
        self.patch_object(chm, 'OpenStackCharm', name='charm')
        self.charm.singleton.get_database_setup.return_value = [
            {'database': 'configuration'}]
        database = mock.MagicMock()
        h.map['shared-db.connected'](database)
        self.charm.singleton.get_database_setup.assert_called_once_with()
        database.configure.assert_called_once_with(database='configuration')
        self.charm.singleton.assess_status.assert_called_once_with()

    def test_default_setup_endpoint_handler(self):
        self.assertIn('identity-service.connected', chm._default_handler_map)
        self.patch_object(chm.reactive, 'when')
        h = self.mock_decorator_gen()
        self.when.side_effect = h.decorator
        # call the default handler installer function, and check its map.
        f = chm._default_handler_map['identity-service.connected']
        f()
        self.assertIn('identity-service.connected', h.map)
        # verify that the installed function works

        OpenStackCharm = mock.MagicMock()

        class Instance(object):
            service_type = 'type1'
            region = 'region1'
            public_url = 'public_url'
            internal_url = 'internal_url'
            admin_url = 'admin_url'
            assess_status = mock.MagicMock()

        OpenStackCharm.singleton = Instance
        with mock.patch.object(chm, 'OpenStackCharm', new=OpenStackCharm):
            keystone = mock.MagicMock()
            h.map['identity-service.connected'](keystone)
            keystone.register_endpoints.assert_called_once_with(
                'type1', 'region1', 'public_url', 'internal_url', 'admin_url')
            Instance.assess_status.assert_called_once_with()

    def test_default_setup_endpoint_available_handler(self):
        self.assertIn('identity-service.available', chm._default_handler_map)
        self.patch_object(chm.reactive, 'when')
        h = self.mock_decorator_gen()
        self.when.side_effect = h.decorator
        # call the default handler installer function, and check its map.
        f = chm._default_handler_map['identity-service.available']
        f()
        self.assertIn('identity-service.available', h.map)
        # verify that the installed function works
        self.patch_object(chm, 'OpenStackCharm', name='charm')
        h.map['identity-service.available']('keystone')
        self.charm.singleton.configure_ssl.assert_called_once_with('keystone')
        self.charm.singleton.assess_status.assert_called_once_with()

    def test_default_config_changed_handler(self):
        self.assertIn('config.changed', chm._default_handler_map)
        self.patch_object(chm.reactive, 'when')
        h = self.mock_decorator_gen()
        self.when.side_effect = h.decorator
        # call the default handler installer function, and check its map.
        f = chm._default_handler_map['config.changed']
        f()
        self.assertIn('config.changed', h.map)
        # verify that the installed function works
        self.patch_object(chm, 'OpenStackCharm', name='charm')
        h.map['config.changed']()
        self.charm.singleton.assess_status.assert_called_once_with()

    def test_default_update_status_handler(self):
        self.assertIn('update-status', chm._default_handler_map)
        self.patch_object(chm.reactive, 'hook')
        h = self.mock_decorator_gen()
        self.hook.side_effect = h.decorator
        # call the default handler installer function, and check its map.
        f = chm._default_handler_map['update-status']
        f()
        self.assertIn('update-status', h.map)
        # verify that the installed function works
        self.patch_object(chm, 'OpenStackCharm', name='charm')
        self.patch_object(chm.hookenv, 'application_version_set')
        h.map['update-status']()
        self.charm.singleton.assess_status.assert_called_once_with()
        self.application_version_set.assert_called_once_with(mock.ANY)

    def test_default_render_configs(self):
        self.patch_object(chm, 'OpenStackCharm', name='charm')
        interfaces = ['a', 'b', 'c']
        chm.default_render_configs(*interfaces)
        self.charm.singleton.render_configs.assert_called_once_with(
            tuple(interfaces))
        self.charm.singleton.assess_status.assert_called_once_with()
