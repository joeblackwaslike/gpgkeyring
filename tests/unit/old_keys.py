import types
from unittest.mock import sentinel
import itertools

import pytest
from zope.interface.verify import verifyClass, verifyObject

import gnupg
import gpgkeyring
from gpgkeyring import exceptions

from ..helpers import constants, util
from ..helpers.unit import testdata

# VARIOUS_KEYS = [
#     testdata.KEYS[0],
#     testdata.FINGERPRINTS[0],
#     testdata.KEYIDS[0],
#     [testdata.FINGERPRINTS[0], testdata.KEYIDS[0], testdata.KEYS[0]],
# ]


@pytest.fixture(params=testdata.FINGERPRINTS + [testdata.FINGERPRINTS])
def fingerprint(request):
    return request.param


@pytest.fixture(params=testdata.KEYIDS + [testdata.KEYIDS])
def keyid(request):
    return request.param


# class TestKeyring:

#     @pytest.fixture(params=testdata.KEY_DUMMIES + [testdata.KEY_DUMMIES])
#     def key(self, request):
#         return request.param

#     def test_keyring_init(self, keyring, gpg_mock):
#         assert keyring._gpg == gpg_mock

#     def test_keyring_class_implements_interface(self, keyring):
#         assert verifyClass(gpgkeyring.interfaces.IKeyring, keyring.__class__)

#     def test_keyring_instance_provides_interface(self, keyring):
#         assert verifyObject(gpgkeyring.interfaces.IKeyring, keyring)

#     def test_keyring__load_for_secret_value(
#         self, keyring_mock, secret, mocker
#     ):
#         result = gpgkeyring.keys.Keyring._load(
#             keyring_mock, secret=secret, event=False
#         )

#         keyring_mock.assert_has_calls(
#             [
#                 mocker.call._gpg._gpg.list_keys(secret=secret),
#                 mocker.call._keylist_class(mocker.ANY),
#             ],
#             any_order=True,
#         )
#         assert result

#     def test_keyring__get_list_for_secret_value(
#         self, keyring_mock, secret, mocker
#     ):
#         result = gpgkeyring.keys.Keyring._get_list(
#             keyring_mock, secret=secret, event=False
#         )

#         keyring_mock.assert_has_calls(
#             [
#                 mocker.call._gpg._gpg.list_keys(secret=secret),
#                 mocker.call._keylist_class(mocker.ANY),
#             ],
#             any_order=True,
#         )
#         assert isinstance(result, gpgkeyring.keys._Keylist)
#         assert result.type == "secret" if secret else "public"

#     def test_keyring_get_all_for_secret_value(self, keyring_mock, secret):
#         result = gpgkeyring.keys.Keyring.get(
#             keyring_mock, secret=secret, event=False
#         )

#         keyring_mock._get_list.assert_called_with(event=False, secret=secret)
#         assert result

#     def test_keyring_get_by_fingerprints_and_secret_value(
#         self, keyring_mock, fingerprint, secret
#     ):
#         keylist_mock = keyring_mock._get_list.return_value
#         result = gpgkeyring.keys.Keyring.get(
#             keyring_mock, fingerprint=fingerprint, secret=secret, event=False
#         )

#         keyring_mock._get_list.assert_called_with(event=False, secret=secret)
#         if isinstance(fingerprint, (list, tuple)):
#             for fp in fingerprint:
#                 keylist_mock.__getitem__.assert_any_call(fp)
#             assert isinstance(result, (tuple, list))
#             assert len(result) == len(fingerprint)
#         else:
#             keylist_mock.__getitem__.assert_called_once_with(fingerprint)
#             assert result

#     def test_keyring_property_for_secret_value(self, keyring_mock, secret):
#         type_ = "secret" if secret else "public"
#         result = gpgkeyring.keys.Keyring.__dict__[type_].__get__(
#             keyring_mock, gpgkeyring.keys.Keyring
#         )
#         keyring_mock.get.assert_called_once_with(secret=secret, event=False)
#         assert bool(result)

#     def test_keyring_generate_key_for_spec(
#         self, keyring_mock, keygen_spec, mocker
#     ):
#         keyring_mock._gpg._gpg.gen_key.return_value = mocker.create_autospec(
#             gnupg.GenKey,
#             instance=True,
#             fingerprint="FINGERPRINT",
#             stderr="KEY_CREATED",
#         )
#         result = gpgkeyring.keys.Keyring.generate(
#             keyring_mock,
#             passphrase=constants.PASSPHRASE,
#             event=False,
#             **keygen_spec
#         )

#         keyring_mock.assert_has_calls(
#             [
#                 mocker.call._keygen_defaults.copy().update(keygen_spec),
#                 mocker.call._keygen_defaults.copy().__setitem__(
#                     "Passphrase", constants.PASSPHRASE
#                 ),
#                 mocker.call._gpg._gpg.gen_key_input(),
#                 mocker.call._gpg._gpg.gen_key(mocker.ANY),
#                 mocker.call.get("FINGERPRINT"),
#             ],
#             any_order=True,
#         )
#         assert result

#     @pytest.mark.parametrize("fingerprints, exportdata", testdata.KEYEXPORTS)
#     def test_keyring_export_by_fingerprints_and_secret_value(
#         self, keyring_mock, fingerprints, exportdata, secret, mocker
#     ):
#         keyring_mock._gpg._gpg.export_keys.return_value = (
#             mocker.create_autospec(
#                 gnupg.ExportResult,
#                 instance=True,
#                 stderr="EXPORT_RES 1",
#                 data=exportdata,
#             )
#         )
#         result = gpgkeyring.keys.Keyring.export(
#             keyring_mock,
#             keys=fingerprints,
#             secret=secret,
#             event=False,
#             passphrase=constants.PASSPHRASE if secret else False,
#         )
#         keyring_mock._gpg._gpg.export_keys.assert_called_once_with(
#             fingerprints,
#             secret=secret,
#             passphrase=constants.PASSPHRASE if secret else False,
#             expect_passphrase=True if secret else False,
#         )
#         assert result == exportdata

#     def test_keyring_export_failure_raises_error(self, keyring_mock, mocker):
#         keyring_mock._gpg._gpg.export_keys.return_value = (
#             mocker.create_autospec(
#                 gnupg.ExportResult, instance=True, stderr="error", data=""
#             )
#         )
#         with pytest.raises(exceptions.KeysExportError):
#             gpgkeyring.keys.Keyring.export(
#                 keyring_mock, keys=sentinel.keys, secret=False, event=False
#             )

#     @pytest.mark.parametrize(
#         "keydata, fingerprints, results", testdata.KEYIMPORTS
#     )
#     def test_keyring_import_keydata(
#         self, keyring_mock, keydata, fingerprints, results, trust_level, mocker
#     ):
#         import_mock = keyring_mock._gpg._gpg.import_keys
#         trust_mock = keyring_mock._gpg._gpg.trust_keys
#         import_mock.return_value = (
#             mocker.create_autospec(
#                 gnupg.ImportResult,
#                 instance=True,
#                 fingerprints=fingerprints,
#                 results=results,
#                 stderr="IMPORT_RES 1",
#             )
#         )
#         if trust_level:
#             trust_mock.return_value = mocker.create_autospec(
#                 gnupg.DeleteResult,
#                 instance=True,
#                 status="ok",
#                 stderr="gpg: inserting ownertrust",
#             )
#         result = gpgkeyring.keys.Keyring.import_(
#             keyring_mock, keydata=keydata, trust=trust_level, event=False
#         )

#         import_mock.assert_called_once_with(keydata)
#         if trust_level:
#             keyring_mock.trust.assert_called_once_with(
#                 fingerprints, level=trust_level
#             )
#         keyring_mock.get.assert_called_once_with(fingerprints)
#         assert result

#     def test_keyring_import_failure_raises_error(self, keyring_mock, mocker):
#         import_mock = keyring_mock._gpg._gpg.import_keys
#         import_mock.return_value = (
#             mocker.create_autospec(
#                 gnupg.ImportResult,
#                 instance=True,
#                 fingerprints=["fingerprint"],
#                 results=[dict(ok="0", text="ERROR")],
#                 stderr="error detail ...",
#             )
#         )
#         with pytest.raises(exceptions.KeysImportError):
#             gpgkeyring.keys.Keyring.import_(
#                 keyring_mock,
#                 keydata="KEYDATA",
#                 trust="TRUST_FULLY",
#                 event=False,
#             )

#     def test_keyring_trust_key_for_level(
#         self, keyring_mock, key, trust_level, mocker
#     ):
#         trust_mock = keyring_mock._gpg._gpg.trust_keys
#         trust_mock.return_value = (
#             mocker.create_autospec(
#                 gnupg.DeleteResult,
#                 instance=True,
#                 status="ok",
#                 stderr="changing ownertrust",
#             )
#         )

#         result = gpgkeyring.keys.Keyring.trust(
#             keyring_mock, keys=key, level=trust_level, event=False
#         )

#         keyring_mock.assert_has_calls(
#             [
#                 mocker.call._gpg._gpg.trust_keys(key, trust_level),
#                 mocker.call._load.cache_clear(),
#                 mocker.call.get(key),
#             ],
#             any_order=True,
#         )
#         assert result

#     def test_keyring_trust_failure_raises_error(self, keyring_mock, mocker):
#         keyring_mock._gpg._gpg.trust_keys.return_value = (
#             mocker.create_autospec(
#                 gnupg.DeleteResult,
#                 instance=True,
#                 status="ok",
#                 stderr="gpg: error in ...",
#             )
#         )

#         with pytest.raises(exceptions.KeysTrustError) as err:
#             gpgkeyring.keys.Keyring.trust(
#                 keyring_mock, keys="KEY", level="TRUST_FULLY", event=False
#             )
#             assert "Error trusting key" in str(err.value)

#     def test_keyring_delete_key(self, keyring_mock, key, secret, mocker):
#         delete_mock = keyring_mock._gpg._gpg.delete_keys
#         delete_mock.return_value = (
#             mocker.create_autospec(
#                 gnupg.DeleteResult,
#                 instance=True,
#                 status="ok",
#                 stderr="KEY_CONSIDERED",
#             )
#         )
#         result = gpgkeyring.keys.Keyring.delete(
#             keyring_mock,
#             keys=key,
#             secret=secret,
#             event=False,
#             passphrase=constants.PASSPHRASE if secret else False,
#         )

#         delete_mock.assert_called_once_with(
#             key,
#             secret=secret,
#             passphrase=constants.PASSPHRASE if secret else False,
#             expect_passphrase=True if secret else False,
#         )
#         assert result is True

#     def test_keyring_delete_key_failure_raises_error(
#         self, keyring_mock, mocker
#     ):
#         keyring_mock._gpg._gpg.delete_keys.return_value = (
#             mocker.create_autospec(
#                 gnupg.DeleteResult,
#                 instance=True,
#                 status="ok",
#                 stderr="delete failed",
#             )
#         )

#         with pytest.raises(exceptions.KeysDeleteError):
#             gpgkeyring.keys.Keyring.delete(
#                 keyring_mock, keys="KEY", secret=False, event=False
#             )

#     def test_keyring_send_key_by_fingerprint_and_keyserver(
#         self, keyring_mock, key, keyserver, mocker
#     ):
#         send_mock = keyring_mock._gpg._gpg.send_keys
#         send_mock.return_value = mocker.create_autospec(
#             gnupg.SendResult, instance=True, stderr="sending key ..."
#         )
#         result = gpgkeyring.keys.Keyring.send(
#             keyring_mock, keys=key, keyserver=keyserver, event=False
#         )

#         send_mock.assert_called_once_with(
#             (keyserver or keyring_mock._gpg._defaults["keyserver"]), key
#         )
#         assert result is True

#     def test_keyring_send_key_failure_raises_error(self, keyring_mock, mocker):
#         keyring_mock._gpg._gpg.send_keys.return_value = mocker.create_autospec(
#             gnupg.SendResult,
#             instance=True,
#             stderr="not a key ID: skipping ...",
#         )

#         with pytest.raises(exceptions.KeysSendError):
#             gpgkeyring.keys.Keyring.send(keyring_mock, keys="KEY", event=False)

#     @pytest.mark.parametrize(
#         "keys, fingerprints, results", testdata.KEYIMPORTS
#     )
#     def test_keyring_receive_key_by_fingerprint_and_keyserver_then_trust(
#         self,
#         keyring_mock,
#         keys,
#         fingerprints,
#         results,
#         keyserver,
#         trust_level,
#         mocker,
#     ):
#         recv_mock = keyring_mock._gpg._gpg.recv_keys
#         recv_mock.return_value = mocker.create_autospec(
#             gnupg.ImportResult,
#             instance=True,
#             results=results,
#             fingerprints=fingerprints,
#             imported=util.safe_len(fingerprints),
#             stderr="IMPORT_OK ...",
#         )
#         result = gpgkeyring.keys.Keyring.receive(
#             keyring_mock,
#             keys=keys,
#             keyserver=keyserver,
#             trust=trust_level,
#             event=False,
#         )

#         recv_mock.assert_called_once_with(
#             (keyserver or keyring_mock._gpg._defaults["keyserver"]), keys
#         )
#         if trust_level:
#             keyring_mock.trust.assert_called_once_with(
#                 fingerprints, level=trust_level
#             )
#         assert result

#     def test_keyring_receive_key_failure_raises_error(
#         self, keyring_mock, trust_level, mocker
#     ):
#         keyring_mock._gpg._gpg.recv_keys.return_value = mocker.create_autospec(
#             gnupg.ImportResult,
#             instance=True,
#             results=[],
#             fingerprints=[],
#             imported=None,
#             stderr="not a key ID: skipping ...",
#         )

#         with pytest.raises(exceptions.KeysReceiveError):
#             gpgkeyring.keys.Keyring.receive(
#                 keyring_mock,
#                 keys="KEY",
#                 keyserver="KEYSERVER",
#                 trust=trust_level,
#                 event=False,
#             )


# class TestKeylist:

#     @pytest.fixture()
#     def keylist_inst(self, keylist, secret):
#         return keylist(secret=secret)

#     @pytest.fixture()
#     def keylist_mock(self, keylist_mock, secret):
#         return keylist_mock(secret=secret)

#     def test_init(self, keylist_inst):
#         assert isinstance(keylist_inst, gpgkeyring.keys._Keylist)
#         assert keylist_inst.type in ("secret", "public")
#         assert isinstance(keylist_inst.current, gpgkeyring.keys.Key)

#     def test_class_implements_interface(self, keylist_inst):
#         assert verifyClass(
#             gpgkeyring.interfaces.IKeylist, keylist_inst.__class__
#         )

#     def test_instance_provides_interface(self, keylist_inst):
#         assert verifyObject(gpgkeyring.interfaces.IKeylist, keylist_inst)

#     def test__get_keys(self, keylist_mock, mocker):
#         keylist_mock.get.side_effect = None
#         result = gpgkeyring.keys._Keylist._get_keys(keylist_mock)

#         keylist_mock.assert_has_calls(
#             [mocker.call.get(key) for key in keylist_mock._wrapped],
#             any_order=True,
#         )
#         for key, val in result.items():
#             assert key in keylist_mock._wrapped
#             assert val

#     def test_get(self, keylist_mock, mocker):
#         for fingerprint in keylist_mock._keylist.fingerprints:
#             result = gpgkeyring.keys._Keylist.get(keylist_mock, fingerprint)

#             keylist_mock._key_class.assert_called_with(
#                 **keylist_mock._wrapped[fingerprint]
#             )
#             assert isinstance(result, gpgkeyring.keys.Key)

#     def test_get_with_bad_keyid_fingerprint_raises_error(
#         self, keylist_mock, mocker
#     ):
#         with pytest.raises(KeyError):
#             gpgkeyring.keys._Keylist.get(keylist_mock, "BAD_KEYVALUE")

#     def test_get_with_bad_keyid_fingerprint_and_default(
#         self, keylist_mock, mocker
#     ):
#         result = gpgkeyring.keys._Keylist.get(
#             keylist_mock, "BAD_KEYVALUE", default=sentinel.default
#         )
#         assert result is sentinel.default

#     def test___getitem__(self, keylist_mock, mocker):
#         for fingerprint in keylist_mock._keylist.fingerprints:
#             result = gpgkeyring.keys._Keylist.__getitem__(
#                 keylist_mock, fingerprint
#             )

#             keylist_mock.get.assert_called_with(fingerprint)
#             assert isinstance(result, gpgkeyring.keys.Key)

#     def test_values(self, keylist_mock, mocker):
#         results = gpgkeyring.keys._Keylist.values(keylist_mock)

#         assert isinstance(results, types.GeneratorType)
#         results = list(results)
#         assert len(results) == len(keylist_mock._keylist.fingerprints)
#         for result in results:
#             assert isinstance(result, gpgkeyring.keys.Key)
#         keylist_mock.assert_has_calls(
#             [
#                 mocker.call._key_class(**keydata)
#                 for keydata in keylist_mock._wrapped.values()
#             ],
#             any_order=True,
#         )
#         keylist_mock._get_keys.assert_called_with()

#     def test_items(self, keylist_mock, mocker):
#         results = gpgkeyring.keys._Keylist.items(keylist_mock)

#         assert isinstance(results, types.GeneratorType)
#         results = list(results)
#         for fingerprint, key in results:
#             assert isinstance(fingerprint, str)
#             assert isinstance(key, gpgkeyring.keys.Key)
#         keylist_mock.assert_has_calls(
#             [
#                 mocker.call._key_class(**keydata)
#                 for keydata in keylist_mock._wrapped.values()
#             ],
#             any_order=True,
#         )
#         keylist_mock._get_keys.assert_called_with()

#     def test_current_property(self, keylist_mock):
#         result = gpgkeyring.keys._Keylist.__dict__["current"].__get__(
#             keylist_mock, gpgkeyring.keys._Keylist
#         )

#         keylist_mock.get.assert_called_with(
#             key=(keylist_mock._keylist.curkey or dict()).get("fingerprint")
#         )
#         assert isinstance(result, gpgkeyring.keys.Key)

#     def test_current_property_works_with_no_keys(self, keylist_mock):
#         keylist_mock.curkey = None
#         self.test_current_property(keylist_mock)

#     def test_fingerprints_property(self, keylist_mock):
#         result = gpgkeyring.keys._Keylist.__dict__["fingerprints"].__get__(
#             keylist_mock, gpgkeyring.keys._Keylist
#         )
#         assert result == list(keylist_mock._wrapped.keys())
#         assert result == keylist_mock._keylist.fingerprints
#         assert isinstance(result, list)
#         for item in result:
#             assert isinstance(item, str)


# class TestKey:

#     def test_init(self, key):
#         assert isinstance(key, gpgkeyring.keys.Key)

#     def test_class_implements_interface(self, key):
#         assert verifyClass(gpgkeyring.interfaces.IKey, key.__class__)

#     def test_instance_provides_interface(self, key):
#         assert verifyObject(gpgkeyring.interfaces.IKey, key)

#     def test_key_type_and_trust_are_enum_values(self, key):
#         assert key.type in testdata.KEY_TYPES
#         for attribute in ("trust", "ownertrust"):
#             assert (
#                 getattr(key, attribute) in testdata.TRUST_LEVELS
#                 + testdata.KEY_VALIDITIES
#             )

#     def test_correct_key_as_bool_value(self, key):
#         assert bool(key) is True

#     def test_key_without_keyid_and_fingerprint_bool_value_is_false(self, key):
#         key.keyid = None
#         key.fingerprint = None
#         assert bool(key) is False

#     def test_containment_checks_subkeys(self, key_mock):
#         subkey_keys = list(key_mock._subkey_info.keys())
#         for sk in subkey_keys:
#             assert gpgkeyring.keys.Key.__contains__(key_mock, sk) is True
#             key_mock._subkey_mock.assert_called_with()

#         subkeys = list(key_mock._get_subkeys().values())
#         for sk in subkeys:
#             assert gpgkeyring.keys.Key.__contains__(key_mock, sk) is True
#             key_mock._subkey_mock.assert_called_with()

#         key_mock._get_subkeys.assert_called_with()

#     def test__getitem__returns_subkey(self, key_mock):
#         subkey_keys = list(key_mock._subkey_info.keys())
#         assert len(subkey_keys) == len(key_mock._subkey_info)
#         for sk in subkey_keys:
#             subkey = gpgkeyring.keys.Key.__getitem__(key_mock, sk)
#             assert isinstance(subkey, gpgkeyring.keys.SubKey)
#             key_mock._subkey_mock.assert_called_with()

#     def test___len__returns_num_of_subkeys(self, key_mock):
#         assert gpgkeyring.keys.Key.__len__(key_mock) == len(key_mock.subkeys)

#     def test__get_subkeys(self, key_mock, mocker):
#         result = gpgkeyring.keys.Key._get_subkeys(key_mock)

#         key_mock.assert_has_calls(
#             [mocker.call.get(subkey_key) for subkey_key in result],
#             any_order=False,
#         )
#         assert result.keys() == key_mock.subkeys.keys()

#     def test_subkeys_property(self, key_mock):
#         result = gpgkeyring.keys.Key.__dict__["subkeys"].__get__(key_mock)
#         assert result.keys() == key_mock.subkeys.keys()
#         key_mock._get_subkeys.assert_called_once_with()

#     def test_get_returns_subkey(self, key_mock):
#         subkey_keys = list(key_mock._subkey_info.keys())
#         key_mock.reset_mock()
#         if subkey_keys:
#             subkey_key = subkey_keys[0]
#             result = gpgkeyring.keys.Key.get(key_mock, subkey_key)
#             key_mock._subkey_class.assert_called_with(
#                 **key_mock._subkey_info[subkey_key]
#             )
#             assert isinstance(result, gpgkeyring.keys.SubKey)

#     def test_keys(self, key_mock):
#         result = list(gpgkeyring.keys.Key.keys(key_mock))
#         assert result == list(key_mock.subkeys.keys())

#     def test_values(self, key_mock):
#         result = list(gpgkeyring.keys.Key.values(key_mock))
#         assert result == list(key_mock.subkeys.values())

#     def test_items(self, key_mock):
#         result = list(gpgkeyring.keys.Key.items(key_mock))
#         assert result == list(key_mock.subkeys.items())


# class TestSubKey:

#     def test_init(self, subkey):
#         assert isinstance(subkey, gpgkeyring.keys.SubKey)

#     def test_class_implements_interface(self, subkey):
#         assert verifyClass(gpgkeyring.interfaces.ISubKey, subkey.__class__)

#     def test_instance_provides_interface(self, subkey):
#         assert verifyObject(gpgkeyring.interfaces.ISubKey, subkey)

#     def test_key_type_and_trust_are_enum_values(self, subkey):
#         assert subkey.type in testdata.KEY_TYPES
#         assert subkey.trust in testdata.TRUST_LEVELS + testdata.KEY_VALIDITIES


# class TestKeyTypes:
#     type_values = gpgkeyring.keys._KEYTYPE_MAP.items()

#     @pytest.fixture(params=testdata.KEY_TYPES)
#     def key_type(self, request):
#         yield request.param

#     def test_key_type_value(self, key_type):
#         assert getattr(gpgkeyring.keys.Types, key_type.name) == key_type

#     def test_trust_level_repr(self, key_type):
#         assert (
#             repr(key_type)
#             == "<{}: {}>".format(type(key_type).__name__, key_type.name)
#         )

#     def test_trust_level_str(self, key_type):
#         assert str(key_type) == key_type.value

#     def test_trust_level_eq_str(self, key_type):
#         assert key_type == str(key_type)

#     @pytest.mark.parametrize("raw, expected", type_values)
#     def test_coerce_trust(self, raw, expected):
#         assert gpgkeyring.keys.coerce_keytype(raw) == expected


# class TestKeyValidities:
#     value_map = gpgkeyring.keys._VALIDITY_MAP
#     trust_values = list(
#         itertools.chain(value_map.items(), gpgkeyring.trust._TRUST_MAP.items())
#     )

#     @pytest.fixture(params=testdata.KEY_VALIDITIES)
#     def validity(self, request):
#         yield request.param

#     def test_validity_value(self, validity):
#         assert getattr(gpgkeyring.keys.Validity, validity.name) == validity

#     def test_validity_repr(self, validity):
#         assert (
#             repr(validity)
#             == "<{}: {}>".format(type(validity).__name__, validity.name)
#         )

#     def test_validity_str(self, validity):
#         assert str(validity) == validity.value

#     def test_validity_eq_str(self, validity):
#         assert validity == str(validity)

#     @pytest.mark.parametrize("raw, expected", trust_values)
#     def test_coerce_validity_trust(self, raw, expected):
#         assert gpgkeyring.keys.coerce_trust_validity(raw) == expected
