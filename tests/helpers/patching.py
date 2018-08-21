import copy
import inspect


def undecorate_class(cls):
    cls = copy.deepcopy(cls)
    methods = [
        name
        for (name, func) in inspect.getmembers(
            cls, predicate=inspect.isfunction
        )
        if not name.startswith("__")
    ]
    for method in methods:
        undecorated = undecorate(getattr(cls, method))
        if undecorated is not getattr(cls, method):
            print("{} is not {}".format(undecorated, getattr(cls, method)))
            setattr(cls, method, undecorated)
    return cls


def undecorate(o):
    """Remove all decorators from a function, method or class"""

    def looks_like_a_decorator(a):
        return (
            inspect.isfunction(a) or inspect.ismethod(a) or inspect.isclass(a)
        )

    if type(o) is type:
        return o

    try:
        closure = o.__closure__
    except AttributeError:
        return

    if closure:
        for cell in closure:
            if cell.cell_contents is o:
                continue
            if looks_like_a_decorator(cell.cell_contents):
                undecd = undecorate(cell.cell_contents)
                if undecd:
                    return undecd
        else:
            return o
    else:
        return o
