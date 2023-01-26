from pygost.iface import PEP247


class GOST34112012(PEP247):
    block_size = ...  # type: int

    def __init__(self, data: bytes = ..., digest_size: int = ...) -> None: ...

    @property
    def digest_size(self) -> int: ...

    def copy(self) -> "GOST34112012": ...

    def update(self, data: bytes) -> None: ...

    def digest(self) -> bytes: ...

    def hexdigest(self) -> str: ...