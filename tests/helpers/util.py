from os.path import join, dirname
import copy
import pickle

import zope.component


def is_nested(*items):
    return isinstance(items[0], (tuple, list))


def safe_len(item, default=1):
    if is_container(item):
        return len(item)
    return default


def is_container(item):
    return isinstance(item, (tuple, list))


def merge_into(d1, **kwargs):
    d1 = copy.deepcopy(d1)
    d1.update(**kwargs)
    return d1


def testdata_path(path, base=__file__):
    return join(dirname(base), "data", path)


def load_testdata(path, mode="rt", base=__file__, unpickle=False):
    path = testdata_path(path, base=base)
    with open(path, mode) as fd:
        data = fd.read()
    if unpickle:
        data = pickle.loads(data)
    return data


def setdefaults(defaults, **kwargs):
    defaults = defaults.copy()
    defaults.update(**kwargs)
    return defaults


def subscribe_event(event):
    _events = []

    @zope.component.adapter(event)
    def _handle_event(_event):
        _events.append(_event)

    registry = zope.component.getGlobalSiteManager()
    registry.registerHandler(_handle_event)

    def return_event():
        assert len(_events) == 1
        return _events.pop()

    return return_event
