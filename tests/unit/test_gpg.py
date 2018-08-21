import pytest
from zope.interface.verify import verifyClass, verifyObject
import zope.component
import gnupg

import gpgkeyring
from gpgkeyring import exceptions, events, interfaces
from gpgkeyring.gpg import GPG

from ..helpers import constants, util


class TestInitialization:
    register_name = "test"

    @pytest.fixture(
        params=[events.BeforeInitializeGPG, events.AfterInitializeGPG]
    )
    def event_class(self, request):
        return request.param

    def test_instance(self, gpg):
        assert isinstance(gpg, GPG)
        assert gpg._gpg._wrapped is gpg

    def test_events(self, gpg_factory, event_class):
        subscription = util.subscribe_event(event_class)
        gpg = gpg_factory(event=True)
        event = subscription()
        if hasattr(event, "gpg"):
            assert isinstance(event.gpg, GPG)
            assert event.gpg == gpg

    def test_override_init_using_before_event(
        self, gpg_factory, registry, mocker, monkeypatch
    ):

        @zope.component.adapter(events.BeforeInitializeGPG)
        def _handle_before(event):
            event.name = "new-name"

        registry.registerHandler(_handle_before)

        monkeypatch.setattr(
            registry,
            "registerUtility",
            mocker.create_autospec(
                registry.registerUtility, side_effect=registry.registerUtility
            ),
        )

        gpg = gpg_factory(event=True, register=True)
        assert gpg.name == "new-name"
        registry.registerUtility.assert_called_once_with(gpg, name="new-name")

    def test_registration(self, gpg_factory, registry):
        gpg = gpg_factory(register=True, name=self.register_name)
        lookup = registry.queryUtility(
            interfaces.IGPG, name=self.register_name
        )
        assert isinstance(lookup, GPG)
        assert lookup is gpg
        assert lookup.name == self.register_name


class TestInterface:
    interface = interfaces.IGPG

    def test_gpg_class_interface(self):
        assert verifyClass(self.interface, GPG)

    def test_gpg_instance_interface(self, gpg):
        assert verifyObject(self.interface, gpg)


class TestEncrypt:
    message = "message"
    ciphertext = b"encrypted-message"
    event_class = events.MessageEncrypted
    response_class = gnupg.Crypt
    response_defaults = dict(
        status="encryption ok", data=ciphertext, stderr=""
    )

    @pytest.fixture(params=[True, False])
    def sign(self, request):
        return request.param

    @pytest.fixture(params=[True, False])
    def symmetric(self, request):
        return request.param

    def mock_response(self, mocker, **kwargs):
        kwargs = util.setdefaults(self.response_defaults, **kwargs)
        return mocker.create_autospec(
            self.response_class, instance=True, **kwargs
        )

    def test_encrypt_message(
        self, gpg_mock, fingerprint, symmetric, sign, mocker
    ):
        gpg_mock._gpg.encrypt.return_value = self.mock_response(mocker)

        result = GPG.encrypt(
            gpg_mock,
            self.message,
            key=fingerprint,
            symmetric=symmetric,
            sign=sign,
            event=False,
        )

        gpg_mock._gpg.encrypt.assert_called_once_with(
            self.message, fingerprint, symmetric=symmetric, sign=sign
        )
        assert result == self.ciphertext.decode()

    def test_encrypt_message_with_default_key(
        self, gpg_mock, mocker, monkeypatch
    ):
        gpg_mock._gpg.encrypt.return_value = self.mock_response(mocker)
        monkeypatch.setattr(gpg_mock.keys.secret, "current", "CURRENT_KEY")

        GPG.encrypt(gpg_mock, self.message, event=False)

        gpg_mock._gpg.encrypt.assert_called_once_with(
            self.message, "CURRENT_KEY", symmetric=False, sign=True
        )

    def test_event(self, gpg_mock, mocker):
        gpg_mock._gpg.encrypt.return_value = self.mock_response(mocker)
        subscription = util.subscribe_event(self.event_class)

        GPG.encrypt(gpg_mock, self.message, key="fingerprint")

        event = subscription()
        assert isinstance(event.gpg, GPG)
        assert event.result.data == self.ciphertext.decode()

    def test_failure_raises_exception(self, gpg_mock, mocker):
        gpg_mock._gpg.encrypt.return_value = self.mock_response(
            mocker, status="encryption failed", stderr="error output"
        )

        with pytest.raises(exceptions.MessageEncryptError):
            GPG.encrypt(gpg_mock, self.message, "fingerprint")


class TestGPGDecrypt:
    message = "message"
    ciphertext = "encrypted-message"
    event_class = events.MessageDecrypted
    response_class = gnupg.Crypt
    response_defaults = dict(
        status="decryption ok",
        data=message.encode(),
        pubkey_fingerprint="FINGERPRINT",
        stderr="",
    )

    def mock_response(self, mocker, **kwargs):
        kwargs = util.setdefaults(self.response_defaults, **kwargs)
        return mocker.create_autospec(
            self.response_class, instance=True, **kwargs
        )

    def test_decrypt_ciphertext(self, gpg_mock, mocker):
        gpg_mock._gpg.decrypt.return_value = self.mock_response(mocker)

        result = GPG.decrypt(gpg_mock, self.ciphertext, event=False)

        gpg_mock._gpg.decrypt.assert_called_once_with(self.ciphertext)
        assert result == self.message

    def test_event(self, gpg_mock, mocker):
        gpg_mock._gpg.decrypt.return_value = self.mock_response(mocker)
        subscription = util.subscribe_event(self.event_class)

        GPG.decrypt(gpg_mock, self.ciphertext)

        event = subscription()
        assert isinstance(event.gpg, GPG)
        assert event.result.data == self.message

    def test_failure_raises_exception(self, gpg_mock, mocker):
        gpg_mock._gpg.decrypt.return_value = self.mock_response(
            mocker, status="decryption failed", stderr="error output"
        )

        with pytest.raises(exceptions.MessageDecryptError):
            GPG.decrypt(gpg_mock, self.ciphertext)


class TestSign:
    message = "message"
    signed = "signed-message"
    event_class = events.MessageSigned
    response_class = gnupg.Sign
    response_defaults = dict(
        status="signature created", data=signed.encode(), stderr=""
    )

    def mock_response(self, mocker, **kwargs):
        kwargs = util.setdefaults(self.response_defaults, **kwargs)
        return mocker.create_autospec(
            self.response_class, instance=True, **kwargs
        )

    def test_sign_message(self, gpg_mock, keyid, mocker):
        gpg_mock._gpg.sign.return_value = self.mock_response(mocker)
        result = GPG.sign(gpg_mock, self.message, key=keyid, event=False)
        gpg_mock._gpg.sign.assert_called_once_with(self.message, keyid=keyid)
        assert result == self.signed

    def test_sign_message_with_default_key(
        self, gpg_mock, mocker, monkeypatch
    ):
        gpg_mock._gpg.sign.return_value = self.mock_response(mocker)
        monkeypatch.setattr(gpg_mock.keys.secret, "current", "CURRENT_KEY")
        GPG.sign(gpg_mock, self.message, event=False)
        gpg_mock._gpg.sign.assert_called_once_with(
            self.message, keyid="CURRENT_KEY"
        )

    def test_event(self, gpg_mock, mocker):
        gpg_mock._gpg.sign.return_value = self.mock_response(mocker)
        subscription = util.subscribe_event(self.event_class)

        GPG.sign(gpg_mock, self.message)
        event = subscription()

        assert isinstance(event.gpg, GPG)
        assert event.result.data == self.signed

    def test_failure_raises_exception(self, gpg_mock, mocker):
        gpg_mock._gpg.sign.return_value = self.mock_response(
            mocker, status="signature failed", stderr="error output"
        )

        with pytest.raises(exceptions.MessageSignError):
            GPG.sign(gpg_mock, self.message)


class TestVerify:
    message = "message"
    signed = "signed-message"
    event_class = events.MessageVerified
    response_class = gnupg.Verify
    response_defaults = dict(
        status="signature valid",
        valid=True,
        pubkey_fingerprint="fingerprint",
        stderr="",
    )

    def mock_response(self, mocker, **kwargs):
        kwargs = util.setdefaults(self.response_defaults, **kwargs)
        return mocker.create_autospec(
            self.response_class, instance=True, **kwargs
        )

    def test_verify_signed_message(self, gpg_mock, mocker):
        gpg_mock._gpg.verify.return_value = self.mock_response(mocker)
        result = GPG.verify(gpg_mock, self.signed, event=False)
        assert result is True

    def test_event(self, gpg_mock, mocker):
        gpg_mock._gpg.verify.return_value = self.mock_response(mocker)
        subscription = util.subscribe_event(self.event_class)

        GPG.verify(gpg_mock, self.signed)
        event = subscription()

        assert isinstance(event.gpg, GPG)
        assert isinstance(event.result, self.response_class)

    def test_failure_raises_exception(self, gpg_mock, mocker):
        gpg_mock._gpg.verify.return_value = self.mock_response(
            mocker,
            status="signature invalid",
            valid=False,
            stderr="error output",
            pubkey_fingerprint=None,
        )

        with pytest.raises(exceptions.MessageVerifyError):
            GPG.verify(gpg_mock, self.signed)


class TestFactoryFunctions:
    interface = interfaces.IGPG
    register_name = "test"
    gpg_options = dict(gnupghome=constants.GNUPGHOME)
    default = "DEFAULT"

    @pytest.fixture
    def gsm_mock(self, registry_mock, monkeypatch):
        monkeypatch.setattr(gpgkeyring.gpg, "_GSM", registry_mock)
        return registry_mock

    def test_create_implements_gpg_factory(self):
        assert verifyClass(interfaces.IGPGFactory, gpgkeyring.create)

    def test_create_queries_gsm(self, gsm_mock):
        gpgkeyring.create(name=self.register_name, **self.gpg_options)
        gsm_mock.queryUtility.assert_called_once_with(
            zope.component.interfaces.IFactory,
            default=gpgkeyring.gpg._gpg_factory,
            name=gpgkeyring.gpg._DEFAULT_GPG_FACTORY_NAME,
        )
        gsm_mock.queryUtility.return_value.assert_called_once_with(
            self.register_name, self.gpg_options
        )

    def test_get_queries_gsm(self, gsm_mock):
        gpgkeyring.get(name=self.register_name, default=self.default)

        gsm_mock.queryUtility.assert_called_once_with(
            interfaces.IGPG, name=self.register_name, default=self.default
        )

    def test_default_factory(self):
        isinstance(gpgkeyring.gpg._gpg_factory, zope.component.factory.Factory)
