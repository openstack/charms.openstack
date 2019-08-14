import json
import hashlib

import charmhelpers.core as core


# TODO(AJK): Once this is in charms.reactive, drop it here and just reference
# the charms.reactive version.
# NOTE(AJK): that we are breaking the camalcase rule as this is acting as a
# context manager, which doesn't look like a 'class'
class is_data_changed(object):
    """ Check if the given set of data has changed since the previous call.
    This works by hashing the JSON-serialization of the data.  Note that, while
    the data will be serialized using ``sort_keys=True``, some types of data
    structures, such as sets, may lead to false positivies.

    The hash of the changed data WON'T be stored until a successful exit of the
    context manager.  This means if the code in the scope of the context
    manager raises an exception, then the data won't be changed and the next
    check will leave it unchanged.  This is to allow for recovery from errors.

    Usage:
        with is_data_changed() as changed:
            charm_instance.some_method()
    """

    def __init__(self, data_id, data, hash_type='md5',
                 no_change_on_exception=True):
        """Initialise the context manager:

        @param data_id: <String> the unique name for this data
        @param data: a JSON serialisable data object.
        @param hash_type: A hashing function available from hashlib
            default='md5'
        @param no_change_on_exception: if an exception is thrown in the managed
            code then the new hash is not persisited.
        """
        self.data_id = data_id
        self.data = data
        self.hash_type = hash_type
        self.no_change_on_exception = no_change_on_exception

    def __enter__(self):
        """with statement as returns boolean"""

        self.key = 'charms.openstack.data_changed.{}'.format(self.data_id)
        alg = getattr(hashlib, self.hash_type)
        serialized = json.dumps(self.data, sort_keys=True).encode('utf8')
        old_hash = core.unitdata.kv().get(self.key)
        self.new_hash = alg(serialized).hexdigest()
        return old_hash != self.new_hash

    def __exit__(self, e_type, *_):
        # If no exception, then store the new hash.
        if e_type is None or not self.no_change_on_exception:
            core.unitdata.kv().set(self.key, self.new_hash)
        # re-raise the exception, if there was one.
        return False
