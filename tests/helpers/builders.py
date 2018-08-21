import operator

from gpgkeyring.keys import Key
import attr


class KeylistDataBuilder:

    class _Context:
        _key_factories = dict(gpgkeyring=Key, gnupg=None)
        _build_strategies = dict(list=list, mapping=dict)

        def __init__(self, builder=None, data=None):
            self.builder = builder
            self.data = data
            self.strategy = None
            self.key_factory = None

        def as_(self, strategy_name):
            self.strategy = self._build_strategies[strategy_name]
            return self

        def as_list(self):
            return self.as_("list")

        def as_mapping(self):
            return self.as_("mapping")

        def _for(self, key_factory_name):
            self.key_factory = self._key_factories[key_factory_name]
            return self.builder.build(
                self.data, self.strategy, self.key_factory
            )

        def for_gnupg(self):
            return self._for("gnupg")

        def for_gpgkeyring(self):
            return self._for("gpgkeyring")

    @classmethod
    def use(cls, data):
        return cls._Context(builder=cls, data=data)

    @classmethod
    def build(cls, data=None, strategy=None, key_factory=None):
        return cls._apply_strategy(
            data, strategy=strategy, key_factory=key_factory
        )

    @classmethod
    def _get_fingerprints(cls, data, getter=None):
        getter = getter or cls._build_getter(name="fingerprint")
        return [getter(item) for item in data]

    @classmethod
    def _build_getter(cls, factory=None, **kwargs):
        factory = factory or operator.itemgetter
        if factory == operator.itemgetter:
            return factory(kwargs["name"])
        raise ValueError("Factory {} not supported")

    @classmethod
    def _apply_strategy(cls, data, strategy=list, key_factory=None):

        def for_each(items):
            return [i for i in items if i in data.key_map]

        def list_builder(fps):
            return [maybe_wrap_key(data.key_map[fp]) for fp in for_each(fps)]

        def dict_builder(fps):
            return {
                fp: maybe_wrap_key(data.key_map[fp]) for fp in for_each(fps)
            }

        def maybe_wrap_key(raw_key):
            return key_factory(**raw_key) if key_factory else raw_key

        build_strategy = {list: list_builder, dict: dict_builder}[strategy]
        fingerprints = cls._get_fingerprints(data)
        attr.set_run_validators(False)

        result = build_strategy(fingerprints)
        attr.set_run_validators(True)
        return result
