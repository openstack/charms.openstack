from unit_tests.utils import BaseTestCase

import charms_openstack.charm.utils as utils


class TestHelpers(BaseTestCase):

    def test_is_data_changed(self):
        class FakeKV(object):
            def __init__(self):
                self.store = {}

            def get(self, key):
                return self.store.get(key, None)

            def set(self, key, value):
                self.store[key] = value

        store = FakeKV()
        self.patch_object(utils.core.unitdata, "kv", new=lambda: store)
        with utils.is_data_changed('foo',
                                   {'foo': 'FOO', 'bar': u'\ua000BAR'}) as f:
            self.assertTrue(f)
        with utils.is_data_changed('foo',
                                   {'foo': 'FOO', 'bar': u'\ua000BAR'}) as f:
            self.assertFalse(f)
        with utils.is_data_changed('bar',
                                   {'foo': 'FOO', 'bar': u'\ua000BAR'}) as f:
            self.assertTrue(f)
        with utils.is_data_changed('bar',
                                   {'foo': 'FOO', 'bar': u'\ua000BAR'}) as f:
            self.assertFalse(f)
        # check that raising an exception doesn't cause a data change
        hash = store.get('charms.openstack.data_changed.bar')
        try:
            with utils.is_data_changed('bar', "string") as f:
                self.assertTrue(f)
                raise Exception()
        except:
            pass
        self.assertEquals(hash, store.get('charms.openstack.data_changed.bar'))
        # check that raising an exception AND having the flag set causes a
        # change
        try:
            with utils.is_data_changed('bar', "string",
                                       no_change_on_exception=False) as f:
                self.assertTrue(f)
                raise Exception()
        except:
            pass
        self.assertNotEquals(hash,
                             store.get('charms.openstack.data_changed.bar'))
