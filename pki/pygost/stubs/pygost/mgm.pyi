from typing import Callable


def nonce_prepare(nonce: bytes) -> bytes: ...


class MGM(object):
    def __init__(
        self,
        encrypter: Callable[[bytes], bytes],
        bs: int,
        tag_size: int = None,
    ) -> None: ...

    def seal(self, nonce: bytes, plaintext: bytes, additional_data: bytes) -> bytes: ...

    def open(self, nonce: bytes, ciphertext: bytes, additional_data: bytes) -> bytes: ...
