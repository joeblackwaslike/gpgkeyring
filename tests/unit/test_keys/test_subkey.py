from zope.interface.verify import verifyClass, verifyObject

from gpgkeyring import interfaces
from gpgkeyring.keys import SubKey

from ...helpers.unit import testdata


class TestSubKey:

    def test_init(self, subkey):
        assert isinstance(subkey, SubKey)

    def test_class_implements_interface(self):
        assert verifyClass(interfaces.ISubKey, SubKey)

    def test_instance_provides_interface(self, subkey):
        assert verifyObject(interfaces.ISubKey, subkey)

    def test_key_type_and_trust_are_enum_values(self, subkey):
        assert subkey.type in testdata.KEY_TYPES
        assert subkey.trust in testdata.TRUST_LEVELS + testdata.KEY_VALIDITIES
