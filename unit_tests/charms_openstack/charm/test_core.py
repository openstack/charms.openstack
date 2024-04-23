import collections
from unittest import mock
import unittest

import charms_openstack.charm.core as chm_core
import charms_openstack.adapters as os_adapters

from unit_tests.charms_openstack.charm.utils import BaseOpenStackCharmTest
from unit_tests.charms_openstack.charm.common import (
    MyAdapter,
    MyOpenStackCharm,
    MyNextOpenStackCharm,
)

import unit_tests.utils as utils

TEST_CONFIG = {'config': True,
               'mandconfig1': 'Iamset',
               'mandconfig2': 'Iamalsoset',
               'mandconfig3': None,
               'openstack-origin': None}
SNAP_MAP = {
    'mysnap': {
        'channel': 'edge',
        'mode': 'jailmode',
    }
}


class TestRegisterOSReleaseSelector(unittest.TestCase):

    def test_register(self):
        save_rsf = chm_core._release_selector_function
        chm_core._release_selector_function = None

        @chm_core.register_os_release_selector
        def test_func():
            pass

        self.assertEqual(chm_core._release_selector_function, test_func)
        chm_core._release_selector_function = save_rsf

    def test_cant_register_more_than_once(self):
        save_rsf = chm_core._release_selector_function
        chm_core._release_selector_function = None

        @chm_core.register_os_release_selector
        def test_func1():
            pass

        with self.assertRaises(RuntimeError):
            @chm_core.register_os_release_selector
            def test_func2():
                pass

        self.assertEqual(chm_core._release_selector_function, test_func1)
        chm_core._release_selector_function = save_rsf


class TestRegisterGetCharmInstance(unittest.TestCase):

    def test_register(self):
        save_rsf = chm_core._get_charm_instance_function
        chm_core._get_charm_instance_function = None

        @chm_core.register_get_charm_instance
        def test_func():
            pass

        self.assertEqual(chm_core._get_charm_instance_function, test_func)
        chm_core._get_charm_instance_function = save_rsf

    def test_cant_register_more_than_once(self):
        save_rsf = chm_core._get_charm_instance_function
        chm_core._get_charm_instance_function = None

        @chm_core.register_get_charm_instance
        def test_func1():
            pass

        with self.assertRaises(RuntimeError):
            @chm_core.register_get_charm_instance
            def test_func2():
                pass

        self.assertEqual(chm_core._get_charm_instance_function, test_func1)
        chm_core._get_charm_instance_function = save_rsf


class TestBaseOpenStackCharmMeta(BaseOpenStackCharmTest):

    def setUp(self):
        super().setUp(chm_core.BaseOpenStackCharm, TEST_CONFIG)

    def test_register_classes(self):
        self.patch_object(chm_core, '_releases', new={})

        class TestC1(chm_core.BaseOpenStackCharm):
            release = 'liberty'

        class TestC2(chm_core.BaseOpenStackCharm):
            release = 'mitaka'

        class TestC3(chm_core.BaseOpenStackCharm):
            release = 'ocata'
            package_type = 'snap'

        self.assertTrue('liberty' in chm_core._releases.keys())
        self.assertTrue('mitaka' in chm_core._releases.keys())
        self.assertTrue('ocata' in chm_core._releases.keys())
        self.assertEqual(chm_core._releases['liberty']['deb'], TestC1)
        self.assertEqual(chm_core._releases['mitaka']['deb'], TestC2)
        self.assertEqual(chm_core._releases['ocata']['snap'], TestC3)

    def test_register_unknown_series(self):
        self.patch_object(chm_core, '_releases', new={})
        with self.assertRaises(RuntimeError):
            class TestC1(chm_core.BaseOpenStackCharm):
                release = 'unknown'

    def test_register_repeated_series(self):
        self.patch_object(chm_core, '_releases', new={})
        with self.assertRaises(RuntimeError):
            class TestC1(chm_core.BaseOpenStackCharm):
                release = 'liberty'

            class TestC2(chm_core.BaseOpenStackCharm):
                release = 'liberty'

    def test_releases_packages_map(self):
        self.maxDiff = None
        self.patch_object(chm_core, '_releases', new={})

        class TestC1(chm_core.BaseOpenStackCharm):
            release = 'liberty'
            packages = ['l_inst_one', 'l_inst_two']
            purge_packages = ['l_purge']

        class TestC2(chm_core.BaseOpenStackCharm):
            release = 'mitaka'
            packages = ['m_inst_one', 'm_inst_two']
            purge_packages = ['m_purge']

        class TestC3(chm_core.BaseOpenStackCharm):
            release = 'ocata'
            package_type = 'snap'
            snaps = ['o_snap_one', 'o_snap_two']

        # from any charm release instance we see package_type / install_purge
        # lists registered by all other charm release instances
        for cls in (TestC1, TestC2, TestC3):
            instance = cls()
            self.assertDictEqual(
                instance.releases_packages_map,
                {
                    'liberty': {
                        'deb': {
                            'install': ['l_inst_one', 'l_inst_two'],
                            'purge': ['l_purge']
                        }
                    },
                    'mitaka': {
                        'deb': {
                            'install': ['m_inst_one', 'm_inst_two'],
                            'purge': ['m_purge']
                        }
                    },
                    'ocata': {
                        'snap': {
                            'install': ['o_snap_one', 'o_snap_two'],
                            'purge': []
                        }
                    }
                }
            )


class TestFunctions(BaseOpenStackCharmTest):

    def setUp(self):
        super().setUp(chm_core.BaseOpenStackCharm, TEST_CONFIG)
        self.patch_object(chm_core, '_releases', new={})
        chm_core._get_charm_instance_function = None

        class TestC1(chm_core.BaseOpenStackCharm):
            release = 'icehouse'

        class TestC2(chm_core.BaseOpenStackCharm):
            release = 'kilo'

        class TestC3(chm_core.BaseOpenStackCharm):
            release = 'mitaka'

        self.C1, self.C2, self.C3 = TestC1, TestC2, TestC3

    def test_get_exact(self):
        self.assertTrue(
            isinstance(chm_core.get_charm_instance(release='icehouse'),
                       self.C1))
        self.assertTrue(
            isinstance(chm_core.get_charm_instance(release='mitaka'), self.C3))

    def test_get_inbetween(self):
        self.assertTrue(
            isinstance(chm_core.get_charm_instance(release='juno'), self.C1))

    def test_fail_too_early_series(self):
        with self.assertRaises(RuntimeError):
            chm_core.get_charm_instance(release='havana')

    def test_get_default_release(self):
        # TODO this may be the wrong logic.  Assume latest release if no
        # release is passed?
        self.assertIsInstance(chm_core.get_charm_instance(), self.C3)

    def test_optional_interfaces(self):
        self.patch_object(chm_core.relations, 'endpoint_from_flag')
        self.endpoint_from_flag.side_effect = ['x', None, 'z']
        r = chm_core.optional_interfaces(
            ('a', 'b', 'c'), 'any', 'old', 'thing')
        self.assertEqual(r, ('a', 'b', 'c', 'x', 'z'))
        self.endpoint_from_flag.assert_has_calls(
            [mock.call('any'), mock.call('old'), mock.call('thing')])


class TestProvideCharmInstance(utils.BaseTestCase):

    def test_provide_charm_instance_as_decorator(self):
        self.patch_object(chm_core, 'BaseOpenStackCharm', name='charm')
        self.charm.singleton = 'the-charm'

        @chm_core.provide_charm_instance
        def the_handler(charm_instance, *args):
            self.assertEqual(charm_instance, 'the-charm')
            self.assertEqual(args, (1, 2, 3))

        the_handler(1, 2, 3)

    def test_provide_charm_instance_as_context_manager(self):
        self.patch_object(chm_core, 'BaseOpenStackCharm', name='charm')
        self.charm.singleton = 'the-charm'

        with chm_core.provide_charm_instance() as charm:
            self.assertEqual(charm, 'the-charm')


class AssessStatusCharm(MyOpenStackCharm):
    release = 'juno'

    @property
    def application_version(self):
        return None


class TestBaseOpenStackCharmAssessStatus(BaseOpenStackCharmTest):

    def setUp(self):
        def make_open_stack_charm():
            return AssessStatusCharm(['interface1', 'interface2'])

        super().setUp(make_open_stack_charm, TEST_CONFIG)

    def test_deferred_assess_status(self):
        self.patch_object(chm_core.hookenv, 'atexit')
        # s = self.target.singleton
        s = self.target
        self.patch_target('_assess_status')
        s.assess_status()
        self._assess_status.assert_not_called()
        self.atexit.assert_called_once_with(mock.ANY)
        self.atexit.reset_mock()
        s.assess_status()
        self.atexit.assert_not_called()
        self._assess_status.assert_not_called()

    def test_assess_status_active(self):
        self.patch_object(chm_core.hookenv, 'status_set')
        # disable all of the check functions
        self.patch_target('check_if_paused', return_value=(None, None))
        self.patch_target('check_interfaces', return_value=(None, None))
        self.patch_target('check_mandatory_config', return_value=(None, None))
        self.patch_target('custom_assess_status_check',
                          return_value=(None, None))
        self.patch_target('check_services_running', return_value=(None, None))
        self.patch_object(chm_core.hookenv, 'application_version_set')
        with mock.patch.object(AssessStatusCharm, 'application_version',
                               new_callable=mock.PropertyMock,
                               return_value="abc"):
            self.target._assess_status()
        self.status_set.assert_called_once_with('active', 'Unit is ready')
        self.application_version_set.assert_called_once_with("abc")
        # check all the check functions got called
        self.check_if_paused.assert_called_once_with()
        self.check_interfaces.assert_called_once_with()
        self.check_mandatory_config.assert_called_once_with()
        self.custom_assess_status_check.assert_called_once_with()
        self.check_services_running.assert_called_once_with()

    def test_assess_status_paused(self):
        self.patch_object(chm_core.hookenv, 'status_set')
        # patch out _ows_check_if_paused
        self.patch_object(chm_core.os_utils, '_ows_check_if_paused',
                          return_value=('paused', '123'))
        self.target._assess_status()
        self.status_set.assert_called_once_with('paused', '123')
        self._ows_check_if_paused.assert_called_once_with(
            services=self.target.services,
            ports=[1, 2, 3, 1234, 2468, 3579])

    def test_states_to_check(self):
        self.patch_target('required_relations', new=['rel1', 'rel2'])
        states = self.target.states_to_check()
        self.assertEqual(
            states,
            {
                'rel1': [
                    ('rel1.connected', 'blocked', "'rel1' missing"),
                    ('rel1.available', 'waiting', "'rel1' incomplete")
                ],
                'rel2': [
                    ('rel2.connected', 'blocked', "'rel2' missing"),
                    ('rel2.available', 'waiting', "'rel2' incomplete")
                ]
            })
        # test override feature of target.states_to_check()
        states = self.target.states_to_check(required_relations=['rel3'])
        self.assertEqual(
            states,
            {
                'rel3': [
                    ('rel3.connected', 'blocked', "'rel3' missing"),
                    ('rel3.available', 'waiting', "'rel3' incomplete")
                ],
            })

    def test_assess_status_check_interfaces(self):
        self.patch_object(chm_core.hookenv, 'status_set')
        self.patch_target('check_if_paused', return_value=(None, None))
        # first check it returns None, None if there are no states
        with mock.patch.object(self.target,
                               'states_to_check',
                               return_value={}):
            self.assertEqual(self.target.check_interfaces(), (None, None))
        # next check that we get back the states we think we should
        self.patch_object(chm_core.reactive.bus,
                          'get_states',
                          return_value={'rel1.connected': 1, })
        self.patch_target('required_relations', new=['rel1', 'rel2'])

        def my_compare(x, y):
            if x is None:
                x = 'unknown'
            if x <= y:
                return x
            return y

        self.patch_object(chm_core.os_utils, 'workload_state_compare',
                          new=my_compare)
        self.assertEqual(self.target.check_interfaces(),
                         ('blocked', "'rel1' incomplete, 'rel2' missing"))
        # check that the assess_status give the same result
        self.target._assess_status()
        self.status_set.assert_called_once_with(
            'blocked', "'rel1' incomplete, 'rel2' missing")

        # Now check it returns None, None if all states are available
        self.get_states.return_value = {
            'rel1.connected': 1,
            'rel1.available': 2,
            'rel2.connected': 3,
            'rel2.available': 4,
        }
        self.assertEqual(self.target.check_interfaces(), (None, None))

    def test_check_mandatory_config_no_mandatory_config(self):
        self.assertEqual(
            self.target.check_mandatory_config(),
            (None, None))

    def test_check_mandatory_config_config_set(self):
        self.target.mandatory_config = ['mandconfig1', 'mandconfig2']
        self.assertEqual(
            self.target.check_mandatory_config(),
            (None, None))

    def test_check_mandatory_config_config_unset(self):
        self.target.mandatory_config = ['mandconfig1', 'mandconfig3']
        self.assertEqual(
            self.target.check_mandatory_config(),
            ('blocked',
             'The following mandatory config is unset: mandconfig3'))

    def test_check_assess_status_check_services_running(self):
        def _svc_and_ports(svc, ports):
            svc.remove('my-second-service')
            ports = [p+10 for p in ports]
            return (svc, ports)
        self.patch_object(
            chm_core.ch_cluster,
            'get_managed_services_and_ports',
            side_effect=_svc_and_ports)
        # verify that the function calls _ows_check_services_running() with the
        # valid information
        self.patch_object(chm_core.os_utils, '_ows_check_services_running',
                          return_value=('active', 'that'))
        status, message = self.target.check_services_running()
        self.assertEqual((status, message), ('active', 'that'))
        self._ows_check_services_running.assert_called_once_with(
            services=['my-default-service'],
            ports=[11, 12, 13, 1244, 2478, 3589])

    def test_check_ports_to_check(self):
        ports = {
            's1': {'k1': 3, 'k2': 4, 'k3': 5},
            's2': {'k4': 6, 'k5': 1, 'k6': 2},
            's3': {'k2': 4, 'k5': 1},
        }
        self.assertEqual(self.target.ports_to_check(ports),
                         [1, 2, 3, 4, 5, 6])


class TestMyOpenStackCharm(BaseOpenStackCharmTest):

    def setUp(self):
        self.save_rsf = chm_core._release_selector_function
        chm_core._release_selector_function = None
        self.save_cif = chm_core._get_charm_instance_function
        chm_core._get_charm_instance_function = None

        def make_open_stack_charm():
            return MyOpenStackCharm(['interface1', 'interface2'])

        super(TestMyOpenStackCharm, self).setUp(make_open_stack_charm,
                                                TEST_CONFIG)

    def tearDown(self):
        chm_core._release_selector_function = self.save_rsf
        chm_core._get_charm_instance_function = self.save_cif
        super().tearDown()

    def test_singleton(self):
        # because we have two releases, we expect this to be the latter.
        # e.g. MyNextOpenStackCharm
        s = self.target.singleton
        self.assertEqual(s.__class__.release, 'mitaka')
        self.assertIsInstance(s, MyOpenStackCharm)
        # should also be the second one, as it's the latest
        self.assertIsInstance(s, MyNextOpenStackCharm)
        self.assertIsInstance(MyOpenStackCharm.singleton,
                              MyOpenStackCharm)
        self.assertIsInstance(chm_core.BaseOpenStackCharm.singleton,
                              MyOpenStackCharm)
        self.assertEqual(s, chm_core.BaseOpenStackCharm.singleton)
        # Note that get_charm_instance() returns NEW instance each time.
        self.assertNotEqual(s, chm_core.get_charm_instance())
        # now clear out the singleton and make sure we get the first one using
        # a release function
        rsf_save = chm_core._release_selector_function
        chm_core._release_selector_function = None

        @chm_core.register_os_release_selector
        def selector():
            return 'icehouse'

        # This should choose the icehouse version instead of the mitaka version
        chm_core._singleton = None
        s = self.target.singleton
        self.assertEqual(s.release, 'icehouse')
        self.assertEqual(s.__class__.release, 'icehouse')
        self.assertFalse(isinstance(s, MyNextOpenStackCharm))
        chm_core._release_selector_function = rsf_save

    def test_install(self):
        # tests that the packages are filtered before installation
        # self.patch_target('set_state')
        self.patch_object(chm_core.charmhelpers.fetch,
                          'filter_installed_packages',
                          return_value=None,
                          name='fip')
        self.fip.side_effect = lambda x: ['p1', 'p2']
        self.patch_object(chm_core.hookenv, 'status_set')
        self.patch_object(chm_core.hookenv, 'apt_install')
        self.patch_object(chm_core.subprocess,
                          'check_output', return_value=b'\n')
        self.patch_object(chm_core.os_utils, 'snap_install_requested')
        self.snap_install_requested.return_value = True
        self.patch_object(chm_core.os_utils, 'install_os_snaps')
        self.patch_object(chm_core.os_utils,
                          'get_snaps_install_info_from_origin',
                          return_value=SNAP_MAP)

        self.target.install()
        # TODO: remove next commented line as we don't set this state anymore
        # self.target.set_state.assert_called_once_with('my-charm-installed')
        self.fip.assert_called_once_with(self.target.packages)
        self.status_set.assert_has_calls([
            mock.call('maintenance', 'Installing packages'),
            mock.call('maintenance', 'Installing snaps'),
            mock.call('maintenance',
                      'Installation complete - awaiting next status')])
        self.install_os_snaps.assert_called_once_with(SNAP_MAP)
        self.get_snaps_install_info_from_origin.assert_called_once_with(
            ['mysnap'],
            None,
            mode='jailmode'
        )
        self.status_set.reset_mock()
        self.fip.side_effect = lambda x: []
        self.snap_install_requested.return_value = False
        self.target.install()
        self.assertFalse(self.status_set.called)

    def test_api_port(self):
        self.assertEqual(self.target.api_port('service1'), 1)
        self.assertEqual(self.target.api_port('service1',
                                              chm_core.os_ip.PUBLIC), 1)
        self.assertEqual(self.target.api_port('service2'), 3)
        with self.assertRaises(KeyError):
            self.target.api_port('service3')
        with self.assertRaises(KeyError):
            self.target.api_port('service2', chm_core.os_ip.INTERNAL)

    def test_update_api_ports(self):
        self.patch_object(chm_core.hookenv, 'open_port')
        self.patch_object(chm_core.hookenv, 'close_port')
        self.patch_object(chm_core.subprocess,
                          'check_output', return_value=b'\n')
        self.target.api_ports = {
            'api': {
                'public': 1,
                'internal': 2,
                'admin': 3,
            },
        }
        test_ports = [4, 5, 6]
        self.target.update_api_ports(test_ports)
        calls = [mock.call(4), mock.call(5), mock.call(6)]
        self.open_port.assert_has_calls(calls)
        self.open_port.reset_mock()
        self.target.update_api_ports()
        calls = [mock.call(1), mock.call(2), mock.call(3)]
        self.open_port.assert_has_calls(calls)
        self.close_port.assert_not_called()
        # now check that it doesn't open ports already open and closes ports
        # that should be closed
        self.open_port.reset_mock()
        self.close_port.reset_mock()
        self.check_output.return_value = b"1/tcp\n2/tcp\n3/udp\n4/tcp\n"
        # port 3 should be opened, port 4 should be closed.
        open_calls = [mock.call(3)]
        close_calls = [mock.call(4)]
        self.target.update_api_ports()
        self.open_port.asset_has_calls(open_calls)
        self.close_port.assert_has_calls(close_calls)

    def test_opened_ports(self):
        self.patch_object(chm_core.subprocess, 'check_output')
        self.check_output.return_value = b'\n'
        self.assertEqual([], self.target.opened_ports())
        self.check_output.return_value = b'1/tcp\n2/tcp\n3/udp\n4/tcp\n5/udp\n'
        self.assertEqual(['1', '2', '4'], self.target.opened_ports())
        self.assertEqual(['1', '2', '4'],
                         self.target.opened_ports(protocol='TCP'))
        self.assertEqual(['3', '5'], self.target.opened_ports(protocol='udp'))
        self.assertEqual(['1/tcp', '2/tcp', '3/udp', '4/tcp', '5/udp'],
                         self.target.opened_ports(protocol=None))
        self.assertEqual([], self.target.opened_ports(protocol='other'))

    def test_render_all_configs(self):
        self.patch_target('render_configs')
        self.target.render_all_configs()
        self.assertEqual(self.render_configs.call_count, 1)
        args = self.render_configs.call_args_list[0][0][0]
        self.assertEqual(['path1', 'path2', 'path3', 'path4'],
                         sorted(args))

    def test_render_configs(self):
        # give us a way to check that the context manager was called.
        from contextlib import contextmanager
        d = [0]

        @contextmanager
        def fake_restart_on_change():
            d[0] += 1
            yield

        self.patch_target('restart_on_change', new=fake_restart_on_change)
        self.patch_object(chm_core.charmhelpers.core.templating, 'render')
        self.patch_object(chm_core.os_templating,
                          'get_loader',
                          return_value='my-loader')
        self.target.render_configs(
            ['path1'],
            adapters_instance=self.target.adapters_instance)
        self.assertEqual(d[0], 1)
        self.render.assert_called_once_with(
            source='path1',
            template_loader='my-loader',
            target='path1',
            context=mock.ANY,
            config_template=None,
            group='root',
            perms=0o640,
        )
        # assert the context was an MyAdapter instance.
        context = self.render.call_args_list[0][1]['context']
        assert isinstance(context, MyAdapter)
        self.assertEqual(context.interfaces, ['interface1', 'interface2'])

        # test source template provided with filename that represents absoulute
        # path of target config where path separators has been replaced by
        # underscores
        self.render.reset_mock()
        self.render.side_effect = [LookupError, None]
        self.target.render_configs(
            ['/etc/some/path1'],
            adapters_instance=self.target.adapters_instance)
        self.render.assert_has_calls([
            mock.call(
                source='path1',
                template_loader='my-loader',
                target='/etc/some/path1',
                context=mock.ANY,
                config_template=None,
                group='root',
                perms=0o640,
            ),
            mock.call(
                source='etc_some_path1',
                template_loader='my-loader',
                target='/etc/some/path1',
                context=mock.ANY,
                config_template=None,
                group='root',
                perms=0o640,
            ),
        ])

    def test_render_configs_construct_adapters_instance(self):
        # give us a way to check that the context manager was called.
        from contextlib import contextmanager
        d = [0]

        @contextmanager
        def fake_restart_on_change():
            d[0] += 1
            yield

        self.patch_target('restart_on_change', new=fake_restart_on_change)
        self.patch_object(chm_core.charmhelpers.core.templating, 'render')
        self.patch_object(chm_core.os_templating,
                          'get_loader',
                          return_value='my-loader')
        self.patch_object(
            chm_core.flags,
            'get_flags',
            return_value=['interface1.available', 'interface2.ready'])
        self.patch_object(
            chm_core.relations,
            'endpoint_from_flag',
            side_effect=lambda x: x.split('.')[0])
        self.target.render_configs(
            ['path1'])
        self.assertEqual(d[0], 1)
        self.render.assert_called_once_with(
            source='path1',
            template_loader='my-loader',
            target='path1',
            context=mock.ANY,
            config_template=None,
            group='root',
            perms=0o640,
        )
        # assert the context was an MyAdapter instance.
        context = self.render.call_args_list[0][1]['context']
        assert isinstance(context, MyAdapter)
        self.assertEqual(context.interfaces, ['interface1', 'interface2'])

    def test_render_config_from_string(self):
        # give us a way to check that the context manager was called.
        from contextlib import contextmanager
        d = [0]

        @contextmanager
        def fake_restart_on_change():
            d[0] += 1
            yield

        self.target.string_templates = {'path1': ('options', 't_prop')}

        self.patch_target('restart_on_change', new=fake_restart_on_change)
        self.patch_object(chm_core.charmhelpers.core.templating, 'render')
        self.patch_object(chm_core.os_templating,
                          'get_loader',
                          return_value='my-loader')

        config_template = 'justatest'
        adapters_instance = self.target.adapters_instance
        adapters_instance.options = mock.MagicMock()
        adapters_instance.options.t_prop = config_template

        self.target.render_configs(
            ['path1'],
            adapters_instance=self.target.adapters_instance)
        self.assertEqual(d[0], 1)
        self.render.assert_called_once_with(
            source='path1',
            template_loader='my-loader',
            target='path1',
            context=mock.ANY,
            config_template=config_template,
            group='root',
            perms=0o640,
        )
        # assert the context was an MyAdapter instance.
        context = self.render.call_args_list[0][1]['context']
        assert isinstance(context, MyAdapter)
        self.assertEqual(context.interfaces, ['interface1', 'interface2'])

    def test_render_config_from_string_no_property(self):
        self.target.string_templates = {'path1': ('options', 't_prop')}

        self.patch_object(chm_core.charmhelpers.core.templating, 'render')
        self.patch_object(chm_core.os_templating,
                          'get_loader',
                          return_value='my-loader')

        adapters_instance = self.target.adapters_instance
        adapters_instance.options = mock.create_autospec(
            os_adapters.ConfigurationAdapter
        )

        self.assertRaises(
            RuntimeError,
            self.target.render_configs, ['path1'],
            adapters_instance=self.target.adapters_instance)

    def test_render_config_from_string_no_relation(self):
        """
        Make sure that if there is no relation adapter yet for a provided
        string template metadata there are no error conditions triggered.
        In other words, 'render' function should not be called while an attempt
        to get a template from an adapter property should be made.
        """
        self.target.string_templates = {'path1': ('options', 't_prop')}
        self.patch_object(chm_core.charmhelpers.core.templating, 'render')
        self.patch_object(chm_core.os_templating,
                          'get_loader',
                          return_value='my-loader')

        with mock.patch.object(MyOpenStackCharm, '_get_string_template',
                               wraps=self.target._get_string_template) as m:

            adapters_instance = self.target.adapters_instance

            self.target.render_configs(
                ['path1'],
                adapters_instance=adapters_instance)
            m.assert_called_once_with('path1', adapters_instance)
            self.render.assert_not_called()

    def test_render_configs_singleton_render_with_interfaces(self):
        self.patch_object(chm_core.charmhelpers.core.templating, 'render')
        self.patch_object(chm_core.os_templating,
                          'get_loader',
                          return_value='my-loader')
        # also patch the cls.adapters_class to ensure that it is called with
        # the target.
        self.patch_object(self.target.singleton, 'adapters_class',
                          return_value='the-context')

        self.target.singleton.render_with_interfaces(
            ['interface1', 'interface2'])

        self.adapters_class.assert_called_once_with(
            ['interface1', 'interface2'], charm_instance=self.target.singleton)

        calls = [
            mock.call(
                source='path1',
                template_loader='my-loader',
                target='path1',
                context=mock.ANY,
                config_template=None,
                group='root',
                perms=0o640,
            ),
            mock.call(
                source='path2',
                template_loader='my-loader',
                target='path2',
                context=mock.ANY,
                config_template=None,
                group='root',
                perms=0o640,
            ),
            mock.call(
                source='path3',
                template_loader='my-loader',
                target='path3',
                context=mock.ANY,
                config_template=None,
                group='root',
                perms=0o755,
            ),
            mock.call(
                source='path4',
                template_loader='my-loader',
                target='path4',
                context=mock.ANY,
                config_template=None,
                group='root',
                perms=0o640,
            ),
        ]
        self.render.assert_has_calls(calls, any_order=True)
        # Assert that None was not passed to render via the context kwarg
        for call in self.render.call_args_list:
            self.assertTrue(call[1]['context'])

    def test_render_configs_singleton_render_with_old_style_interfaces(self):
        # Test for fix to Bug #1623917
        self.patch_object(chm_core.charmhelpers.core.templating, 'render')
        self.patch_object(chm_core.os_templating,
                          'get_loader',
                          return_value='my-loader')

        class OldSkoolAdapter(object):
            def __init__(self, interfaces):
                pass
        self.patch_object(self.target.singleton, 'adapters_class')
        self.adapters_class.side_effect = OldSkoolAdapter

        self.target.singleton.render_with_interfaces(
            ['interface1', 'interface2'])

        adapter_calls = [
            mock.call(
                ['interface1', 'interface2'],
                charm_instance=self.target.singleton),
            mock.call(
                ['interface1', 'interface2'])]
        self.adapters_class.assert_has_calls(adapter_calls)

        calls = [
            mock.call(
                source='path1',
                template_loader='my-loader',
                target='path1',
                context=mock.ANY,
                config_template=None,
                group='root',
                perms=0o640,
            ),
            mock.call(
                source='path2',
                template_loader='my-loader',
                target='path2',
                context=mock.ANY,
                config_template=None,
                group='root',
                perms=0o640,
            ),
            mock.call(
                source='path3',
                template_loader='my-loader',
                target='path3',
                context=mock.ANY,
                config_template=None,
                group='root',
                perms=0o755,
            ),
            mock.call(
                source='path4',
                template_loader='my-loader',
                target='path4',
                context=mock.ANY,
                config_template=None,
                group='root',
                perms=0o640,
            ),
        ]
        self.render.assert_has_calls(calls, any_order=True)
        # Assert that None was not passed to render via the context kwarg
        for call in self.render.call_args_list:
            self.assertTrue(call[1]['context'])

    def test_get_closest_release_match(self):
        # this is mocked universally in unit_tests/__init__.py so we have
        # to apply to not so great mock on top to allow the method to be
        # called.

        def fake_version_compare(a, b):
            if a > b:
                return 1
            elif a < b:
                return -1

            return 0

        self.patch_object(chm_core.charmhelpers.fetch.apt_pkg,
                          'version_compare')
        chm_core.charmhelpers.fetch.apt_pkg.version_compare.side_effect = \
            fake_version_compare

        codenames = collections.OrderedDict([('3.9', 'ussuri'),
                                             ('4.0', 'victoria'),
                                             ('4.0.1', 'yoga')])

        pkg_ver = '4'
        release = self.target.get_closest_release_match(pkg_ver, codenames)
        chm_core.charmhelpers.fetch.apt_pkg.version_compare.assert_has_calls([
            mock.call('4.0.1', pkg_ver), mock.call('4.0', pkg_ver)])
        self.assertEqual(release, None)

        chm_core.charmhelpers.fetch.apt_pkg.version_compare.reset_mock()
        pkg_ver = '4.0'
        release = self.target.get_closest_release_match(pkg_ver, codenames)
        chm_core.charmhelpers.fetch.apt_pkg.version_compare.assert_has_calls([
            mock.call('4.0.1', pkg_ver), mock.call('4.0', pkg_ver)])
        self.assertEqual(release, ('4.0', 'victoria'))

        chm_core.charmhelpers.fetch.apt_pkg.version_compare.reset_mock()
        pkg_ver = '4.0.1'
        release = self.target.get_closest_release_match(pkg_ver, codenames)
        chm_core.charmhelpers.fetch.apt_pkg.version_compare.assert_has_calls([
            mock.call('4.0.1', pkg_ver)])
        self.assertEqual(release, ('4.0.1', 'yoga'))

        chm_core.charmhelpers.fetch.apt_pkg.version_compare.reset_mock()
        pkg_ver = '4.0.2'
        release = self.target.get_closest_release_match(pkg_ver, codenames)
        chm_core.charmhelpers.fetch.apt_pkg.version_compare.assert_has_calls([
            mock.call('4.0.1', pkg_ver)])
        self.assertEqual(release, ('4.0.1', 'yoga'))

        chm_core.charmhelpers.fetch.apt_pkg.version_compare.reset_mock()
        codenames['4.0.3'] = 'antelope'
        pkg_ver = '4.0.2'
        release = self.target.get_closest_release_match(pkg_ver, codenames)
        chm_core.charmhelpers.fetch.apt_pkg.version_compare.assert_has_calls([
            mock.call('4.0.3', pkg_ver), mock.call('4.0.1', pkg_ver)])
        self.assertEqual(release, ('4.0.1', 'yoga'))

        chm_core.charmhelpers.fetch.apt_pkg.version_compare.reset_mock()
        release = self.target.get_closest_release_match('4.0.1.1', codenames)
        chm_core.charmhelpers.fetch.apt_pkg.version_compare.assert_has_calls([
            mock.call('4.0.1', '4.0.1.1')])
        self.assertEqual(release, ('4.0.1', 'yoga'))

        chm_core.charmhelpers.fetch.apt_pkg.version_compare.reset_mock()
        pkg_ver = '4.4.1+git2022033113.2339b9e9-0ubuntu1'
        release = self.target.get_closest_release_match(pkg_ver, codenames)
        chm_core.charmhelpers.fetch.apt_pkg.version_compare.assert_has_calls([
            mock.call('4.0.3', pkg_ver)])
        self.assertEqual(release, ('4.0.3', 'antelope'))

    def test_get_os_codename_package(self):
        # this is mocked universally in unit_tests/__init__.py so we have
        # to apply to not so great mock on top to allow the method to be
        # called.

        def fake_version_compare(a, b):
            if a > b:
                return 1
            elif a < b:
                return -1

            return 0

        self.patch_object(chm_core.charmhelpers.fetch.apt_pkg,
                          'version_compare')
        chm_core.charmhelpers.fetch.apt_pkg.version_compare.side_effect = \
            fake_version_compare

        codenames = {
            'testpkg': collections.OrderedDict([
                ('2', 'mitaka'),
                ('3', 'newton'),
                ('4', 'ocata'), ])}
        self.patch_object(chm_core.charmhelpers.fetch, 'apt_cache')
        pkg_mock = mock.MagicMock()
        self.apt_cache.return_value = {
            'testpkg': pkg_mock}
        self.patch_object(chm_core.charmhelpers.fetch.apt_pkg,
                          'upstream_version')
        self.patch_object(chm_core.os_utils, 'snap_install_requested',
                          return_value=False)
        self.patch_object(chm_core.os_utils, 'get_installed_os_version')
        self.get_installed_os_version.return_value = None
        self.upstream_version.return_value = '3.0.0~b1'
        self.patch_object(self.target, 'get_closest_release_match')
        self.get_closest_release_match.return_value = (3, 'newton')
        self.patch_object(self.target, 'configure_source')
        self.configure_source.side_effect = KeyError

        self.assertEqual(
            chm_core.BaseOpenStackCharm().get_os_codename_package(
                'testpkg', codenames),
            'newton')
        self.upstream_version.assert_called_once_with(
            pkg_mock.current_ver.ver_str)
        self.upstream_version.reset_mock()
        self.assertEqual(
            chm_core.BaseOpenStackCharm().get_os_codename_package(
                'testpkg', codenames, apt_cache_sufficient=True),
            'newton')
        self.upstream_version.assert_called_once_with(
            pkg_mock.version)
        # Test Wallaby
        self.get_installed_os_version.return_value = 'wallaby'
        self.assertEqual(
            chm_core.BaseOpenStackCharm().get_os_codename_package(
                'testpkg', codenames),
            'wallaby')
        # Test non-fatal fail
        self.get_installed_os_version.return_value = None
        self.assertEqual(
            chm_core.BaseOpenStackCharm().get_os_codename_package(
                'unknownpkg', codenames, fatal=False),
            None)
        # Test fatal fail
        with self.assertRaises(Exception):
            chm_core.BaseOpenStackCharm().get_os_codename_package(
                'unknownpkg', codenames, fatal=True)
        with self.assertRaises(ValueError):
            chm_core.BaseOpenStackCharm().get_os_codename_package(
                'unknownpkg', codenames, fatal=True)

    def test_get_os_version_package(self):
        self.patch_target('package_codenames')
        self.patch_target('get_os_codename_package',
                          return_value='my-series')
        self.patch_object(chm_core.os_utils, 'snap_install_requested',
                          return_value=False)
        self.assertEqual(
            self.target.get_os_version_package('testpkg'),
            '2011.2')
        # Test unknown codename
        self.patch_target('get_os_codename_package',
                          return_value='unknown-series')
        self.assertEqual(self.target.get_os_version_package('testpkg'), None)

    def test_openstack_upgrade_available_package(self):
        self.patch_target('get_os_version_package')
        self.patch_object(chm_core.os_utils, 'get_os_version_install_source')
        self.patch_object(chm_core.charmhelpers.fetch, 'apt_pkg')
        self.patch_target('config',
                          new={'openstack-origin': 'cloud:natty-folsom'})
        self.patch_object(chm_core.os_utils, 'snap_install_requested',
                          return_value=False)
        self.get_os_version_package.return_value = 2
        self.get_os_version_install_source.return_value = 3
        self.target.openstack_upgrade_available(package='testpkg')
        self.apt_pkg.version_compare.assert_called_once_with(3, 2)

    def test_openstack_upgrade_available_snap(self):
        self.patch_target('get_os_version_snap')
        self.patch_object(chm_core.os_utils, 'get_os_version_install_source')
        self.patch_object(chm_core.charmhelpers.fetch, 'apt_pkg')
        self.patch_target('config',
                          new={'openstack-origin': 'snap:ocata/stable'})
        self.patch_object(chm_core.os_utils, 'snap_install_requested',
                          return_value=True)
        self.get_os_version_snap.return_value = 2
        self.get_os_version_install_source.return_value = 3
        self.target.openstack_upgrade_available(snap='testsnap')
        self.get_os_version_snap.assert_called_once_with('testsnap')
        self.apt_pkg.version_compare.assert_called_once_with(3, 2)

    def test_upgrade_if_available(self):
        self.patch_target('run_upgrade')
        self.patch_target('openstack_upgrade_available', return_value=True)
        self.patch_target('config',
                          new={'action-managed-upgrade': False})
        self.target.upgrade_if_available('int_list')
        self.run_upgrade.assert_called_once_with(interfaces_list='int_list')

    def test_upgrade_if_available_none_available(self):
        self.patch_target('run_upgrade')
        self.patch_target('openstack_upgrade_available', return_value=False)
        self.target.upgrade_if_available('int_list')
        self.assertFalse(self.run_upgrade.called)

    def test_upgrade_if_available_action_managed_on(self):
        self.patch_target('run_upgrade')
        self.patch_target('openstack_upgrade_available', return_value=True)
        self.patch_target('config',
                          new={'action-managed-upgrade': True})
        self.assertFalse(self.run_upgrade.called)

    def test_run_upgrade(self):
        self.patch_object(chm_core.hookenv, 'status_set')
        self.patch_target('do_openstack_upgrade_db_migration')
        self.patch_target('do_openstack_pkg_upgrade')
        self.patch_target('do_openstack_upgrade_config_render')
        self.patch_target('do_openstack_upgrade_db_migration')
        self.patch_target('config',
                          new={'openstack-origin': 'snap:ocata/stable'})
        self.patch_object(chm_core, 'get_charm_instance')
        target_charm = mock.MagicMock()
        self.get_charm_instance.return_value = target_charm
        self.target.run_upgrade('int_list')
        self.status_set.assert_called_once_with('maintenance',
                                                'Running openstack upgrade')
        target_charm.do_openstack_pkg_upgrade.assert_called_once_with()
        (target_charm.do_openstack_upgrade_config_render.
            assert_called_once_with('int_list'))
        (target_charm.do_openstack_upgrade_db_migration.
            assert_called_once_with())

    def test_remove_obsolete_packages(self):
        self.patch_object(chm_core.charmhelpers.fetch, 'apt_purge')
        self.patch_object(chm_core.charmhelpers.fetch, 'apt_autoremove')
        self.patch_object(chm_core.charmhelpers.fetch,
                          'filter_installed_packages',
                          return_value=['python-notinstalled'])
        self.assertTrue(self.target.remove_obsolete_packages())
        self.apt_purge.assert_called_once_with(
            packages=['python-obsolete'],
            fatal=True)
        self.apt_autoremove.assert_called_once_with(
            purge=True,
            fatal=True)

    def test_remove_obsolete_packages_noop(self):
        self.patch_object(chm_core.charmhelpers.fetch, 'apt_purge')
        self.patch_object(chm_core.charmhelpers.fetch, 'apt_autoremove')
        self.patch_object(chm_core.charmhelpers.fetch,
                          'filter_installed_packages',
                          return_value=self.target.purge_packages)
        self.assertFalse(self.target.remove_obsolete_packages())
        self.apt_purge.assert_not_called()
        self.apt_autoremove.assert_not_called()

    def test_do_openstack_pkg_upgrade_package(self):
        self.patch_target('config',
                          new={'openstack-origin': 'cloud:natty-kilo'})
        self.patch_object(chm_core.os_utils, 'get_os_codename_install_source')
        self.patch_object(chm_core.os_utils, 'get_source_and_pgp_key')
        self.patch_object(chm_core.hookenv, 'log')
        self.patch_object(chm_core.charmhelpers.fetch, 'add_source')
        self.patch_object(chm_core.charmhelpers.fetch, 'apt_update')
        self.patch_object(chm_core.charmhelpers.fetch, 'apt_upgrade')
        self.patch_object(chm_core.charmhelpers.fetch, 'apt_install')
        self.patch_object(chm_core.charmhelpers.fetch, 'apt_purge')
        self.patch_object(chm_core.charmhelpers.fetch, 'apt_autoremove')
        self.patch_object(chm_core.charmhelpers.fetch,
                          'filter_installed_packages',
                          return_value=['python-notinstalled'])
        self.patch_object(chm_core.os_utils, 'snap_install_requested',
                          return_value=False)
        self.get_source_and_pgp_key.return_value = ('cloud:natty-kilo', None)
        self.target.do_openstack_pkg_upgrade()
        self.add_source.assert_called_once_with(
            'cloud:natty-kilo', None)
        self.apt_update.assert_called_once_with()
        self.apt_upgrade.assert_called_once_with(
            dist=True, fatal=True,
            options=[
                '--option', 'Dpkg::Options::=--force-confnew', '--option',
                'Dpkg::Options::=--force-confdef'])
        self.apt_install.assert_called_once_with(
            packages=self.target.all_packages,
            options=[
                '--option', 'Dpkg::Options::=--force-confnew', '--option',
                'Dpkg::Options::=--force-confdef'],
            fatal=True)
        self.apt_purge.assert_called_once_with(
            packages=['python-obsolete'],
            fatal=True)
        self.apt_autoremove.assert_called_once_with(
            purge=True,
            fatal=True)

    def test_do_openstack_pkg_upgrade_snap(self):
        self.patch_target('config',
                          new={'openstack-origin': 'snap:ocata/stable'})
        self.patch_object(chm_core.os_utils, 'get_os_codename_install_source')
        self.patch_object(chm_core.hookenv, 'log')
        self.patch_object(chm_core.os_utils, 'get_source_and_pgp_key')
        self.patch_object(chm_core.charmhelpers.fetch, 'add_source')
        self.patch_object(chm_core.charmhelpers.fetch, 'apt_update')
        self.patch_object(chm_core.charmhelpers.fetch, 'apt_upgrade')
        self.patch_object(chm_core.charmhelpers.fetch, 'apt_install')
        self.patch_object(chm_core.os_utils, 'snap_install_requested',
                          return_value=True)
        self.patch_object(chm_core.os_utils, 'install_os_snaps')
        self.patch_object(chm_core.os_utils,
                          'get_snaps_install_info_from_origin',
                          return_value=SNAP_MAP)
        self.get_source_and_pgp_key.return_value = ('snap:ocata/stable', None)
        self.target.do_openstack_pkg_upgrade()
        self.add_source.assert_called_once_with(
            'snap:ocata/stable', None)
        self.apt_update.assert_called_once_with()
        self.apt_upgrade.assert_called_once_with(
            dist=True, fatal=True,
            options=[
                '--option', 'Dpkg::Options::=--force-confnew', '--option',
                'Dpkg::Options::=--force-confdef'])
        self.apt_install.assert_called_once_with(
            packages=self.target.all_packages,
            options=[
                '--option', 'Dpkg::Options::=--force-confnew', '--option',
                'Dpkg::Options::=--force-confdef'],
            fatal=True)
        self.install_os_snaps.assert_called_once_with(snaps=SNAP_MAP,
                                                      refresh=True)
        self.get_snaps_install_info_from_origin.assert_called_once_with(
            ['mysnap'],
            'snap:ocata/stable',
            mode='jailmode',
        )

    def test_do_openstack_upgrade_config_render(self):
        self.patch_target('render_with_interfaces')
        self.target.do_openstack_upgrade_config_render('int_list')
        self.target.render_with_interfaces.assert_called_once_with(
            'int_list')

    def test_do_openstack_upgrade_db_migration(self):
        self.patch_object(chm_core.hookenv, 'is_leader')
        self.patch_object(chm_core.subprocess, 'check_call')
        self.patch_object(chm_core.hookenv, 'log')
        # Check migration not run if not leader
        self.is_leader.return_value = False
        self.target.do_openstack_upgrade_db_migration()
        self.assertFalse(self.check_call.called)
        # Check migration run on leader
        self.is_leader.return_value = True
        self.target.do_openstack_upgrade_db_migration()
        self.check_call.assert_called_once_with(['my-sync-cmd', 'param1'])

    def test_upgrade_charm(self):
        self.target.update_api_ports = mock.MagicMock()
        self.target.install = mock.MagicMock()
        self.target.remove_obsolete_packages = mock.MagicMock()
        self.target.remove_obsolete_packages.return_value = True
        self.target.restart_all = mock.MagicMock()
        self.target.upgrade_charm()
        self.target.update_api_ports.assert_called_once()
        self.target.install.assert_called_once()
        self.target.remove_obsolete_packages.assert_called_once()
        self.target.restart_all.assert_called_once()

    def test_upgrade_charm_no_purge(self):
        self.target.update_api_ports = mock.MagicMock()
        self.target.install = mock.MagicMock()
        self.target.remove_obsolete_packages = mock.MagicMock()
        self.target.remove_obsolete_packages.return_value = False
        self.target.restart_all = mock.MagicMock()
        self.target.upgrade_charm()
        self.target.update_api_ports.assert_called_once()
        self.target.install.assert_called_once()
        self.target.remove_obsolete_packages.assert_called_once()
        self.target.restart_all.assert_not_called()

    def test_service_stop(self):
        self.patch_object(chm_core.ch_host, 'service_stop')
        self.target.service_stop('test-svc')
        self.service_stop.assert_called_once_with('test-svc')

    def test_service_start(self):
        self.patch_object(chm_core.ch_host, 'service_start')
        self.target.service_start('test-svc')
        self.service_start.assert_called_once_with('test-svc')

    def test_service_restart(self):
        self.patch_object(chm_core.ch_host, 'service_restart')
        self.target.service_restart('test-svc')
        self.service_restart.assert_called_once_with('test-svc')

    def test_service_reload(self):
        self.patch_object(chm_core.ch_host, 'service_reload')
        self.target.service_reload('test-svc')
        self.service_reload.assert_called_once_with('test-svc', False)
