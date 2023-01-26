from typing import Callable


def pad_size(data_size: int, blocksize: int) -> int: ...


def pad1(data: bytes, blocksize: int) -> bytes: ...


def pad2(data: bytes, blocksize: int) -> bytes: ...


def unpad2(data: bytes, blocksize: int) -> bytes: ...


def pad3(data: bytes, blocksize: int) -> bytes: ...


def ecb_encrypt(encrypter: Callable[[bytes], bytes], bs: int, pt: bytes) -> bytes: ...


def ecb_decrypt(decrypter: Callable[[bytes], bytes], bs: int, ct: bytes) -> bytes: ...


def acpkm(encrypter: Callable[[bytes], bytes], bs: int) -> bytes: ...


def ctr(encrypter: Callable[[bytes], bytes], bs: int, data: bytes, iv: bytes) -> bytes: ...


def ctr_acpkm(
        algo_class: object,
        encrypter: Callable[[bytes], bytes],
        section_size: int,
        bs: int,
        data: bytes,
        iv: bytes,
) -> bytes: ...


def ofb(encrypter: Callable[[bytes], bytes], bs: int, data: bytes, iv: bytes) -> bytes: ...


def cbc_encrypt(encrypter: Callable[[bytes], bytes], bs: int, pt: bytes, iv: bytes) -> bytes: ...


def cbc_decrypt(decrypter: Callable[[bytes], bytes], bs: int, ct: bytes, iv: bytes) -> bytes: ...


def cfb_encrypt(encrypter: Callable[[bytes], bytes], bs: int, pt: bytes, iv: bytes) -> bytes: ...


def cfb_decrypt(encrypter: Callable[[bytes], bytes], bs: int, ct: bytes, iv: bytes) -> bytes: ...


def mac(encrypter: Callable[[bytes], bytes], bs: int, data: bytes) -> bytes: ...


def acpkm_master(
        algo_class: object,
        encrypter: Callable[[bytes], bytes],
        key_section_size: int,
        bs: int,
        keymat_len: int,
) -> bytes: ...


def mac_acpkm_master(
        algo_class: object,
        encrypter: Callable[[bytes], bytes],
        key_section_size: int,
        section_size: int,
        bs: int,
        data: bytes,
) -> bytes: ...


def pad_iso10126(data: bytes, blocksize: int) -> bytes: ...


def unpad_iso10126(data: bytes, blocksize: int) -> bytes: ...
