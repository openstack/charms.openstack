# Note that the unit_tests/__init__.py has the following lines to stop
# side effects from the imorts from charm helpers.

# sys.path.append('./lib')
# mock out some charmhelpers libraries as they have apt install side effects
# sys.modules['charmhelpers.contrib.openstack.utils'] = mock.MagicMock()
# sys.modules['charmhelpers.contrib.network.ip'] = mock.MagicMock()

import unittest
import mock

import charm.openstack.adapters as adapters


class MyRelation(object):

    auto_accessors = ['this', 'that']
    relation_name = 'my-name'

    def this(self):
        return 'this'

    def that(self):
        return 'that'

    def some(self):
        return 'thing'


class TestOpenStackRelationAdapter(unittest.TestCase):

    def test_class(self):
        ad = adapters.OpenStackRelationAdapter(MyRelation(), ['some'])
        self.assertEqual(ad.this, 'this')
        self.assertEqual(ad.that, 'that')
        self.assertEqual(ad.some, 'thing')
        self.assertEqual(ad.relation_name, 'my-name')
        with self.assertRaises(AttributeError):
            ad.relation_name = 'hello'


class FakeRabbitMQRelation():

    auto_accessors = ['vip', 'private_address']
    relation_name = 'amqp'

    def __init__(self, vip=None):
        self._vip = vip

    def vip(self):
        return self._vip

    def private_address(self):
        return 'private-address'

    def rabbitmq_hosts(self):
        return ['host1', 'host2']

    def vhost(self):
        return 'vhost'

    def username(self):
        return 'fakename'


class TestRabbitMQRelationAdapter(unittest.TestCase):

    def test_class(self):
        fake = FakeRabbitMQRelation(None)
        mq = adapters.RabbitMQRelationAdapter(fake)
        self.assertEqual(mq.vhost, 'vhost')
        self.assertEqual(mq.username, 'fakename')
        self.assertEqual(mq.host, 'private-address')
        # TODO: can't do the following 2 lines as not dynamic accessors
        # fake._vip = 'vip1'
        # self.assertEqual(mq.host, 'vip1')
        self.assertEqual(mq.hosts, 'host1,host2')


class FakeDatabaseRelation():

    auto_accessors = []
    relation_name = 'shared_db'

    def db_host(self):
        return 'host1'

    def username(self, prefix=''):
        return 'username1{}'.format(prefix)

    def password(self, prefix=''):
        return 'password1{}'.format(prefix)

    def database(self, prefix=''):
        return 'database1{}'.format(prefix)


class SSLDatabaseRelationAdapter(adapters.DatabaseRelationAdapter):

    ssl_ca = 'my-ca'
    ssl_cert = 'my-cert'
    ssl_key = 'my-key'


class TestDatabaseRelationAdapter(unittest.TestCase):

    def test_class(self):
        fake = FakeDatabaseRelation()
        db = adapters.DatabaseRelationAdapter(fake)
        self.assertEqual(db.host, 'host1')
        self.assertEqual(db.type, 'mysql')
        self.assertEqual(db.password, 'password1')
        self.assertEqual(db.username, 'username1')
        self.assertEqual(db.database, 'database1')
        self.assertEqual(db.uri, 'mysql://username1:password1@host1/database1')
        self.assertEqual(db.get_uri('x'),
                         'mysql://username1x:password1x@host1/database1x')
        # test the ssl feature of the base class
        db = SSLDatabaseRelationAdapter(fake)
        self.assertEqual(db.uri,
                         'mysql://username1:password1@host1/database1'
                         '?ssl_ca=my-ca'
                         '&ssl_cert=my-cert&ssl_key=my-key')


class TestConfigurationAdapter(unittest.TestCase):

    def test_class(self):
        test_config = {
            'one': 1,
            'two': 2,
            'three': 3,
            'that-one': 4
        }
        with mock.patch.object(adapters.charmhelpers.core.hookenv, 'config',
                               new=lambda: test_config):
            c = adapters.ConfigurationAdapter()
            self.assertEqual(c.one, 1)
            self.assertEqual(c.three, 3)
            self.assertEqual(c.that_one, 4)


class TestOpenStackRelationAdapters(unittest.TestCase):
    # test the OpenStackRelationAdapters() class, and then derive from it to
    # test the additonal relation_adapters member on __init__

    def test_class(self):
        test_config = {
            'one': 1,
            'two': 2,
            'three': 3,
            'that-one': 4
        }
        with mock.patch.object(adapters.charmhelpers.core.adapters.hookenv,
                               'config',
                               new=lambda: test_config):
            amqp = FakeRabbitMQRelation()
            shared_db = FakeDatabaseRelation()
            mine = MyRelation()
            a = adapters.OpenStackRelationAdapters([amqp, shared_db, mine])
            self.assertEqual(a.amqp.private_address, 'private-address')
            self.assertEqual(a.my_name.this, 'this')
            items = list(a)
            self.assertEqual(items[0][0], 'amqp')
            self.assertEqual(items[1][0], 'shared_db')
            self.assertEqual(items[2][0], 'my_name')
            self.assertEqual(items[3][0], 'options')


class MyRelationAdapter(adapters.OpenStackRelationAdapter):

    @property
    def us(self):
        return self.this + '-us'


class MyOpenStackRelationAdapters(adapters.OpenStackRelationAdapters):

    relation_adapters = {
        'my_name': MyRelationAdapter,
    }


class TestCustomOpenStackRelationAdapters(unittest.TestCase):

    def test_class(self):
        test_config = {
            'one': 1,
            'two': 2,
            'three': 3,
            'that-one': 4
        }
        with mock.patch.object(adapters.charmhelpers.core.adapters.hookenv,
                               'config',
                               new=lambda: test_config):
            amqp = FakeRabbitMQRelation()
            shared_db = FakeDatabaseRelation()
            mine = MyRelation()
            a = MyOpenStackRelationAdapters([amqp, shared_db, mine])
            self.assertEqual(a.my_name.us, 'this-us')
