from pygost.iface import PEP247


class MAC(PEP247):
    def __init__(
        self,
        key: bytes,
        data: bytes = ...,
        iv: bytes = ...,
        sbox: str = ...,
    ) -> None: ...

    @property
    def digest_size(self) -> int: ...

    def copy(self) -> "MAC": ...

    def update(self, data: bytes) -> None: ...

    def digest(self) -> bytes: ...

    def hexdigest(self) -> str: ...


def new(key: bytes, data: bytes = ..., iv: bytes = ..., sbox: str = ...) -> MAC: ...
