import secrets


def random_hexdata(length=40):
    return secrets.token_bytes(length).hex()[:length].upper()


def gen_fingerprint():
    return random_hexdata()


def gen_keyid():
    return random_hexdata(16)


class KeyDummy:

    def __init__(self, keyid=None, fingerprint=None, **kwargs):
        self.keyid = keyid
        self.fingerprint = fingerprint
        self.__dict__.update(kwargs)
