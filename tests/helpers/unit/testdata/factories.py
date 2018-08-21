from ...util import load_testdata


KEYDATA = load_testdata("public.pem", base=__file__)


def gen_keyimport_data(fingerprint):
    return (
        KEYDATA,
        [fingerprint],
        [dict(fingerprint=fingerprint, ok="1", text="imported")],
    )


def gen_keyexport_data(fingerprint):
    if isinstance(fingerprint, (tuple, list)):
        return tuple([list(fingerprint), [KEYDATA for fp in fingerprint]])
    return fingerprint, KEYDATA
