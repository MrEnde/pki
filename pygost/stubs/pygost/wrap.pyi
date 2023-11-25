from typing import Callable


def wrap_gost(ukm: bytes, kek: bytes, cek: bytes, sbox: str = ...) -> bytes: ...


def unwrap_gost(kek: bytes, data: bytes, sbox: str = ...) -> bytes: ...


def wrap_cryptopro(ukm: bytes, kek: bytes, cek: bytes, sbox: str = ...) -> bytes: ...


def unwrap_cryptopro(kek: bytes, data: bytes, sbox: str = ...) -> bytes: ...


def kexp15(
        encrypter_key: Callable[[bytes], bytes],
        encrypter_mac: Callable[[bytes], bytes],
        bs: int,
        key: bytes,
        iv: bytes,
) -> bytes: ...


def kimp15(
        encrypter_key: Callable[[bytes], bytes],
        encrypter_mac: Callable[[bytes], bytes],
        bs: int,
        kexp: bytes,
        iv: bytes,
) -> bytes: ...
