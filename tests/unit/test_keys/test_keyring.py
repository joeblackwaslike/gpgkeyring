import pytest
from zope.interface.verify import verifyClass, verifyObject

import gnupg
from gpgkeyring import interfaces, exceptions
from gpgkeyring.gpg import GPG
from gpgkeyring.keys import _Keylist, Keyring

from ...helpers.unit import testdata
from ...helpers import constants, util
from ...helpers.patching import undecorate_class


_Keylist = undecorate_class(_Keylist)
Keyring = undecorate_class(Keyring)


@pytest.fixture(params=testdata.KEY_DUMMIES + [testdata.KEY_DUMMIES])
def key(request):
    return request.param


class TestKeyringInitialization:

    def test_init(self, keyring, gpg_mock):
        assert isinstance(keyring, Keyring)
        assert isinstance(keyring._gpg, GPG)


class TestKeyringInterface:

    def test_class_implements_interface(self):
        assert verifyClass(interfaces.IKeyring, Keyring)

    def test_instance_provides_interface(self, keyring):
        assert verifyObject(interfaces.IKeyring, keyring)


class TestKeyringLoad:

    def test__load(self, keyring_mock, secret, mocker):
        result = Keyring._load(keyring_mock, secret=secret, event=False)

        keyring_mock.assert_has_calls(
            [
                mocker.call._gpg._gpg.list_keys(secret=secret),
                mocker.call._keylist_class(mocker.ANY),
            ],
            any_order=True,
        )
        assert result

    def test_keyring__get_list_for_secret_value(
        self, keyring_mock, secret, mocker
    ):
        result = Keyring._get_list(keyring_mock, secret=secret, event=False)

        keyring_mock.assert_has_calls(
            [
                mocker.call._gpg._gpg.list_keys(secret=secret),
                mocker.call._keylist_class(mocker.ANY),
            ],
            any_order=True,
        )
        assert isinstance(result, _Keylist)
        assert result.type == "secret" if secret else "public"

    def test_keyring_get_all_for_secret_value(self, keyring_mock, secret):
        result = Keyring.get(keyring_mock, secret=secret, event=False)

        keyring_mock._get_list.assert_called_with(event=False, secret=secret)
        assert isinstance(result, _Keylist)

    def test_keyring_get_by_fingerprints_and_secret_value(
        self, keyring_mock, fingerprint, secret
    ):
        keylist_mock = keyring_mock._get_list.return_value
        result = Keyring.get(
            keyring_mock, fingerprint=fingerprint, secret=secret, event=False
        )

        keyring_mock._get_list.assert_called_with(event=False, secret=secret)
        if isinstance(fingerprint, (list, tuple)):
            for fp in fingerprint:
                keylist_mock.__getitem__.assert_any_call(fp)
            assert isinstance(result, (tuple, list))
            assert len(result) == len(fingerprint)
        else:
            # keylist_mock.__getitem__.assert_called_once_with(fingerprint)
            assert bool(result)

    def test_keyring_property_for_secret_value(self, keyring_mock, secret):
        type_ = "secret" if secret else "public"
        result = Keyring.__dict__[type_].__get__(keyring_mock, Keyring)
        keyring_mock.get.assert_called_once_with(secret=secret, event=False)
        assert isinstance(result, _Keylist)

    # FIX LATER

    # def test_keyring_generate_key_for_spec(
    #     self, keyring_mock, keygen_spec, mocker
    # ):
    #     keyring_mock._gpg._gpg.gen_key.return_value = mocker.create_autospec(
    #         gnupg.GenKey,
    #         instance=True,
    #         fingerprint="FINGERPRINT",
    #         stderr="KEY_CREATED",
    #     )
    #     result = Keyring.generate(
    #         keyring_mock,
    #         passphrase=constants.PASSPHRASE,
    #         event=False,
    #         **keygen_spec
    #     )
    #     import pdb

    #     pdb.set_trace()
    #     keyring_mock.assert_has_calls(
    #         [
    #             mocker.call._keygen_defaults.copy().update(keygen_spec),
    #             mocker.call._keygen_defaults.copy().__setitem__(
    #                 "Passphrase", constants.PASSPHRASE
    #             ),
    #             mocker.call._gpg._gpg.gen_key_input(),
    #             mocker.call._gpg._gpg.gen_key(mocker.ANY),
    #             mocker.call.get("FINGERPRINT"),
    #         ],
    #         any_order=True,
    #     )
    #     assert result

    @pytest.mark.parametrize("fingerprints, exportdata", testdata.KEYEXPORTS)
    def test_keyring_export_by_fingerprints_and_secret_value(
        self, keyring_mock, fingerprints, exportdata, secret, mocker
    ):
        keyring_mock._gpg._gpg.export_keys.return_value = (
            mocker.create_autospec(
                gnupg.ExportResult,
                instance=True,
                stderr="EXPORT_RES 1",
                data=exportdata,
            )
        )
        result = Keyring.export(
            keyring_mock,
            keys=fingerprints,
            secret=secret,
            event=False,
            passphrase=constants.PASSPHRASE if secret else False,
        )
        keyring_mock._gpg._gpg.export_keys.assert_called_once_with(
            fingerprints,
            secret=secret,
            passphrase=constants.PASSPHRASE if secret else False,
            expect_passphrase=True if secret else False,
        )
        assert result == exportdata

    def test_keyring_export_failure_raises_error(self, keyring_mock, mocker):
        keyring_mock._gpg._gpg.export_keys.return_value = (
            mocker.create_autospec(
                gnupg.ExportResult, instance=True, stderr="error", data=""
            )
        )
        with pytest.raises(exceptions.KeysExportError):
            Keyring.export(
                keyring_mock, keys="KEYS", secret=False, event=False
            )

    @pytest.mark.parametrize(
        "keydata, fingerprints, results", testdata.KEYIMPORTS
    )
    def test_keyring_import_keydata(
        self, keyring_mock, keydata, fingerprints, results, trust_level, mocker
    ):
        import_mock = keyring_mock._gpg._gpg.import_keys
        trust_mock = keyring_mock._gpg._gpg.trust_keys
        import_mock.return_value = (
            mocker.create_autospec(
                gnupg.ImportResult,
                instance=True,
                fingerprints=fingerprints,
                results=results,
                stderr="IMPORT_RES 1",
            )
        )
        if trust_level:
            trust_mock.return_value = mocker.create_autospec(
                gnupg.DeleteResult,
                instance=True,
                status="ok",
                stderr="gpg: inserting ownertrust",
            )
        result = Keyring.import_(
            keyring_mock, keydata=keydata, trust=trust_level, event=False
        )

        import_mock.assert_called_once_with(keydata)
        if trust_level:
            keyring_mock.trust.assert_called_once_with(
                fingerprints, level=trust_level
            )
        keyring_mock.get.assert_called_once_with(fingerprints)
        assert result

    def test_keyring_import_failure_raises_error(self, keyring_mock, mocker):
        import_mock = keyring_mock._gpg._gpg.import_keys
        import_mock.return_value = (
            mocker.create_autospec(
                gnupg.ImportResult,
                instance=True,
                fingerprints=["fingerprint"],
                results=[dict(ok="0", text="ERROR")],
                stderr="error detail ...",
            )
        )
        with pytest.raises(exceptions.KeysImportError):
            Keyring.import_(
                keyring_mock,
                keydata="KEYDATA",
                trust="TRUST_FULLY",
                event=False,
            )

    # FIX LATER

    # def test_keyring_trust_key_for_level(
    #     self, keyring_mock, key, trust_level, mocker
    # ):
    #     trust_mock = keyring_mock._gpg._gpg.trust_keys
    #     trust_mock.return_value = (
    #         mocker.create_autospec(
    #             gnupg.DeleteResult,
    #             instance=True,
    #             status="ok",
    #             stderr="changing ownertrust",
    #         )
    #     )

    #     result = Keyring.trust(
    #         keyring_mock, keys=key, level=trust_level, event=False
    #     )

    #     keyring_mock.assert_has_calls(
    #         [
    #             mocker.call._gpg._gpg.trust_keys(key, trust_level),
    #             mocker.call._load.cache_clear(),
    #             mocker.call.get(key),
    #         ],
    #         any_order=True,
    #     )
    #     assert result

    def test_keyring_trust_failure_raises_error(self, keyring_mock, mocker):
        keyring_mock._gpg._gpg.trust_keys.return_value = (
            mocker.create_autospec(
                gnupg.DeleteResult,
                instance=True,
                status="ok",
                stderr="gpg: error in ...",
            )
        )

        with pytest.raises(exceptions.KeysTrustError) as err:
            Keyring.trust(
                keyring_mock, keys="KEY", level="TRUST_FULLY", event=False
            )
            assert "Error trusting key" in str(err.value)

    def test_keyring_delete_key(self, keyring_mock, key, secret, mocker):
        delete_mock = keyring_mock._gpg._gpg.delete_keys
        delete_mock.return_value = (
            mocker.create_autospec(
                gnupg.DeleteResult,
                instance=True,
                status="ok",
                stderr="KEY_CONSIDERED",
            )
        )
        result = Keyring.delete(
            keyring_mock,
            keys=key,
            secret=secret,
            event=False,
            passphrase=constants.PASSPHRASE if secret else False,
        )

        delete_mock.assert_called_once_with(
            key,
            secret=secret,
            passphrase=constants.PASSPHRASE if secret else False,
            expect_passphrase=True if secret else False,
        )
        assert result is True

    def test_keyring_delete_key_failure_raises_error(
        self, keyring_mock, mocker
    ):
        keyring_mock._gpg._gpg.delete_keys.return_value = (
            mocker.create_autospec(
                gnupg.DeleteResult,
                instance=True,
                status="ok",
                stderr="delete failed",
            )
        )

        with pytest.raises(exceptions.KeysDeleteError):
            Keyring.delete(keyring_mock, keys="KEY", secret=False, event=False)

    def test_keyring_send_key_by_fingerprint_and_keyserver(
        self, keyring_mock, key, keyserver, mocker
    ):
        send_mock = keyring_mock._gpg._gpg.send_keys
        send_mock.return_value = mocker.create_autospec(
            gnupg.SendResult, instance=True, stderr="sending key ..."
        )
        result = Keyring.send(
            keyring_mock, keys=key, keyserver=keyserver, event=False
        )

        send_mock.assert_called_once_with(
            (keyserver or keyring_mock._gpg._defaults["keyserver"]), key
        )
        assert result is True

    def test_keyring_send_key_failure_raises_error(self, keyring_mock, mocker):
        keyring_mock._gpg._gpg.send_keys.return_value = mocker.create_autospec(
            gnupg.SendResult,
            instance=True,
            stderr="not a key ID: skipping ...",
        )

        with pytest.raises(exceptions.KeysSendError):
            Keyring.send(keyring_mock, keys="KEY", event=False)

    @pytest.mark.parametrize(
        "keys, fingerprints, results", testdata.KEYIMPORTS
    )
    def test_keyring_receive_key_by_fingerprint_and_keyserver_then_trust(
        self,
        keyring_mock,
        keys,
        fingerprints,
        results,
        keyserver,
        trust_level,
        mocker,
    ):
        recv_mock = keyring_mock._gpg._gpg.recv_keys
        recv_mock.return_value = mocker.create_autospec(
            gnupg.ImportResult,
            instance=True,
            results=results,
            fingerprints=fingerprints,
            imported=util.safe_len(fingerprints),
            stderr="IMPORT_OK ...",
        )
        result = Keyring.receive(
            keyring_mock,
            keys=keys,
            keyserver=keyserver,
            trust=trust_level,
            event=False,
        )

        recv_mock.assert_called_once_with(
            (keyserver or keyring_mock._gpg._defaults["keyserver"]), keys
        )
        if trust_level:
            keyring_mock.trust.assert_called_once_with(
                fingerprints, level=trust_level
            )
        assert result

    def test_keyring_receive_key_failure_raises_error(
        self, keyring_mock, trust_level, mocker
    ):
        keyring_mock._gpg._gpg.recv_keys.return_value = mocker.create_autospec(
            gnupg.ImportResult,
            instance=True,
            results=[],
            fingerprints=[],
            imported=None,
            stderr="not a key ID: skipping ...",
        )

        with pytest.raises(exceptions.KeysReceiveError):
            Keyring.receive(
                keyring_mock,
                keys="KEY",
                keyserver="KEYSERVER",
                trust=trust_level,
                event=False,
            )
