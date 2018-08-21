import types

import pytest

from gpgkeyring.decorators import expires_cache, passthru


@pytest.fixture()
def spy(mocker):
    mock = mocker.MagicMock(
        instance=True,
        test_expires=mocker.MagicMock(side_effect=lambda self, arg: arg),
        test_wrapped=mocker.MagicMock(
            __name__="test_wrapped", side_effect=lambda self, arg: arg
        ),
        _wrapped=mocker.MagicMock(
            instance=True,
            test_wrapped=mocker.MagicMock(
                __name__="test_wrapped", side_effect=lambda arg: arg
            ),
        ),
    )
    mock._expires_mock = mock.test_expires
    mock._wrapped_mock = mock.test_wrapped

    mock.test_expires = types.MethodType(
        expires_cache(mock.test_expires), mock
    )
    mock.test_wrapped = types.MethodType(passthru(mock.test_wrapped), mock)
    return mock


class TestDecorators:

    def test_expires_cache_decorator(self, spy, mocker):
        result = spy.test_expires("arg")
        spy._load.cache_clear.assert_has_calls([mocker.call(), mocker.call()])
        spy._expires_mock.assert_called_once_with(spy, "arg")
        assert result == "arg"

    def test_passthru_decorator(self, spy, mocker):
        result = spy.test_wrapped("arg")

        spy._wrapped.test_wrapped.assert_called_once_with("arg")
        spy._wrapped_mock.assert_not_called()
        assert result == "arg"
