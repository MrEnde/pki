# coding: utf-8
# PyGOST -- Pure Python GOST cryptographic functions library
# Copyright (C) 2015-2022 Sergey Matveev <stargrave@stargrave.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""GOST R 34.13-2015: Modes of operation for block ciphers

This module currently includes only padding methods.
"""

from os import urandom

from pygost.utils import bytes2long
from pygost.utils import long2bytes
from pygost.utils import strxor
from pygost.utils import xrange


KEYSIZE = 32


def pad_size(data_size, blocksize):
    """Calculate required pad size to full up blocksize
    """
    if data_size < blocksize:
        return blocksize - data_size
    if data_size % blocksize == 0:
        return 0
    return blocksize - data_size % blocksize


def pad1(data, blocksize):
    """Padding method 1

    Just fill up with zeros if necessary.
    """
    return data + b"\x00" * pad_size(len(data), blocksize)


def pad2(data, blocksize):
    """Padding method 2 (also known as ISO/IEC 7816-4)

    Add one bit and then fill up with zeros.
    """
    return data + b"\x80" + b"\x00" * pad_size(len(data) + 1, blocksize)


def unpad2(data, blocksize):
    """Unpad method 2
    """
    last_block = bytearray(data[-blocksize:])
    pad_index = last_block.rfind(b"\x80")
    if pad_index == -1:
        raise ValueError("Invalid padding")
    for c in last_block[pad_index + 1:]:
        if c != 0:
            raise ValueError("Invalid padding")
    return data[:-(blocksize - pad_index)]


def pad3(data, blocksize):
    """Padding method 3
    """
    if pad_size(len(data), blocksize) == 0:
        return data
    return pad2(data, blocksize)


def ecb_encrypt(encrypter, bs, pt):
    """ECB encryption mode of operation

    :param encrypter: encrypting function, that takes block as an input
    :param int bs: cipher's blocksize, bytes
    :param bytes pt: already padded plaintext
    """
    if not pt or len(pt) % bs != 0:
        raise ValueError("Plaintext is not blocksize aligned")
    ct = []
    for i in xrange(0, len(pt), bs):
        ct.append(encrypter(pt[i:i + bs]))
    return b"".join(ct)


def ecb_decrypt(decrypter, bs, ct):
    """ECB decryption mode of operation

    :param decrypter: Decrypting function, that takes block as an input
    :param int bs: cipher's blocksize, bytes
    :param bytes ct: ciphertext
    """
    if not ct or len(ct) % bs != 0:
        raise ValueError("Ciphertext is not blocksize aligned")
    pt = []
    for i in xrange(0, len(ct), bs):
        pt.append(decrypter(ct[i:i + bs]))
    return b"".join(pt)


def acpkm(encrypter, bs):
    """Perform ACPKM key derivation

    :param encrypter: encrypting function, that takes block as an input
    :param int bs: cipher's blocksize, bytes
    """
    return b"".join([
        encrypter(bytes(bytearray(range(d, d + bs))))
        for d in range(0x80, 0x80 + bs * (KEYSIZE // bs), bs)
    ])


def ctr(encrypter, bs, data, iv, _acpkm=None):
    """Counter mode of operation

    :param encrypter: encrypting function, that takes block as an input
    :param int bs: cipher's blocksize, bytes
    :param bytes data: plaintext/ciphertext
    :param bytes iv: half blocksize-sized initialization vector

    For decryption you use the same function again.
    """
    if len(iv) != bs // 2:
        raise ValueError("Invalid IV size")
    if len(data) > bs * (1 << (8 * (bs // 2 - 1))):
        raise ValueError("Too big data")
    stream = []
    ctr_value = 0
    ctr_max_value = 1 << (8 * (bs // 2))
    if _acpkm is not None:
        acpkm_algo_class, acpkm_section_size_in_bs = _acpkm
        acpkm_section_size_in_bs //= bs
    for _ in xrange(0, len(data) + pad_size(len(data), bs), bs):
        if (
                _acpkm is not None and
                ctr_value != 0 and
                ctr_value % acpkm_section_size_in_bs == 0
        ):
            encrypter = acpkm_algo_class(acpkm(encrypter, bs)).encrypt
        stream.append(encrypter(iv + long2bytes(ctr_value, bs // 2)))
        ctr_value = (ctr_value + 1) % ctr_max_value
    return strxor(b"".join(stream), data)


def ctr_acpkm(algo_class, encrypter, section_size, bs, data, iv):
    """CTR-ACPKM mode of operation

    :param algo_class: pygost.gost3412's algorithm class
    :param encrypter: encrypting function, that takes block as an input
    :param int section_size: ACPKM'es section size (N), in bytes
    :param int bs: cipher's blocksize, bytes
    :param bytes data: plaintext/ciphertext
    :param bytes iv: half blocksize-sized initialization vector

    For decryption you use the same function again.
    """
    if section_size % bs != 0:
        raise ValueError("section_size must be multiple of bs")
    return ctr(encrypter, bs, data, iv, _acpkm=(algo_class, section_size))


def ofb(encrypter, bs, data, iv):
    """OFB mode of operation

    :param encrypter: encrypting function, that takes block as an input
    :param int bs: cipher's blocksize, bytes
    :param bytes data: plaintext/ciphertext
    :param bytes iv: blocksize-sized initialization vector

    For decryption you use the same function again.
    """
    if len(iv) < bs or len(iv) % bs != 0:
        raise ValueError("Invalid IV size")
    r = [iv[i:i + bs] for i in range(0, len(iv), bs)]
    result = []
    for i in xrange(0, len(data) + pad_size(len(data), bs), bs):
        r = r[1:] + [encrypter(r[0])]
        result.append(strxor(r[-1], data[i:i + bs]))
    return b"".join(result)


def cbc_encrypt(encrypter, bs, pt, iv):
    """CBC encryption mode of operation

    :param encrypter: encrypting function, that takes block as an input
    :param int bs: cipher's blocksize, bytes
    :param bytes pt: already padded plaintext
    :param bytes iv: blocksize-sized initialization vector
    """
    if not pt or len(pt) % bs != 0:
        raise ValueError("Plaintext is not blocksize aligned")
    if len(iv) < bs or len(iv) % bs != 0:
        raise ValueError("Invalid IV size")
    r = [iv[i:i + bs] for i in range(0, len(iv), bs)]
    ct = []
    for i in xrange(0, len(pt), bs):
        ct.append(encrypter(strxor(r[0], pt[i:i + bs])))
        r = r[1:] + [ct[-1]]
    return b"".join(ct)


def cbc_decrypt(decrypter, bs, ct, iv):
    """CBC decryption mode of operation

    :param decrypter: Decrypting function, that takes block as an input
    :param int bs: cipher's blocksize, bytes
    :param bytes ct: ciphertext
    :param bytes iv: blocksize-sized initialization vector
    """
    if not ct or len(ct) % bs != 0:
        raise ValueError("Ciphertext is not blocksize aligned")
    if len(iv) < bs or len(iv) % bs != 0:
        raise ValueError("Invalid IV size")
    r = [iv[i:i + bs] for i in range(0, len(iv), bs)]
    pt = []
    for i in xrange(0, len(ct), bs):
        blk = ct[i:i + bs]
        pt.append(strxor(r[0], decrypter(blk)))
        r = r[1:] + [blk]
    return b"".join(pt)


def cfb_encrypt(encrypter, bs, pt, iv):
    """CFB encryption mode of operation

    :param encrypter: encrypting function, that takes block as an input
    :param int bs: cipher's blocksize, bytes
    :param bytes pt: plaintext
    :param bytes iv: blocksize-sized initialization vector
    """
    if len(iv) < bs or len(iv) % bs != 0:
        raise ValueError("Invalid IV size")
    r = [iv[i:i + bs] for i in range(0, len(iv), bs)]
    ct = []
    for i in xrange(0, len(pt) + pad_size(len(pt), bs), bs):
        ct.append(strxor(encrypter(r[0]), pt[i:i + bs]))
        r = r[1:] + [ct[-1]]
    return b"".join(ct)


def cfb_decrypt(encrypter, bs, ct, iv):
    """CFB decryption mode of operation

    :param encrypter: encrypting function, that takes block as an input
    :param int bs: cipher's blocksize, bytes
    :param bytes ct: ciphertext
    :param bytes iv: blocksize-sized initialization vector
    """
    if len(iv) < bs or len(iv) % bs != 0:
        raise ValueError("Invalid IV size")
    r = [iv[i:i + bs] for i in range(0, len(iv), bs)]
    pt = []
    for i in xrange(0, len(ct) + pad_size(len(ct), bs), bs):
        blk = ct[i:i + bs]
        pt.append(strxor(encrypter(r[0]), blk))
        r = r[1:] + [blk]
    return b"".join(pt)


def _mac_shift(bs, data, xor_lsb=0):
    num = (bytes2long(data) << 1) ^ xor_lsb
    return long2bytes(num, bs)[-bs:]


Rb64 = 0b11011
Rb128 = 0b10000111


def _mac_ks(encrypter, bs):
    Rb = Rb128 if bs == 16 else Rb64
    _l = encrypter(bs * b"\x00")
    k1 = _mac_shift(bs, _l, Rb) if bytearray(_l)[0] & 0x80 > 0 else _mac_shift(bs, _l)
    k2 = _mac_shift(bs, k1, Rb) if bytearray(k1)[0] & 0x80 > 0 else _mac_shift(bs, k1)
    return k1, k2


def mac(encrypter, bs, data):
    """MAC (known here as CMAC, OMAC1) mode of operation

    :param encrypter: encrypting function, that takes block as an input
    :param int bs: cipher's blocksize, bytes
    :param bytes data: data to authenticate

    Implementation is based on PyCrypto's CMAC one, that is in public domain.
    """
    k1, k2 = _mac_ks(encrypter, bs)
    if len(data) % bs == 0:
        tail_offset = len(data) - bs
    else:
        tail_offset = len(data) - (len(data) % bs)
    prev = bs * b"\x00"
    for i in xrange(0, tail_offset, bs):
        prev = encrypter(strxor(data[i:i + bs], prev))
    tail = data[tail_offset:]
    return encrypter(strxor(
        strxor(pad3(tail, bs), prev),
        k1 if len(tail) == bs else k2,
    ))


def acpkm_master(algo_class, encrypter, key_section_size, bs, keymat_len):
    """ACPKM-Master key derivation

    :param algo_class: pygost.gost3412's algorithm class
    :param encrypter: encrypting function, that takes block as an input
    :param int key_section_size: ACPKM'es key section size (T*), in bytes
    :param int bs: cipher's blocksize, bytes
    :param int keymat_len: length of key material to produce
    """
    return ctr_acpkm(
        algo_class,
        encrypter,
        key_section_size,
        bs,
        data=b"\x00" * keymat_len,
        iv=b"\xFF" * (bs // 2),
    )


def mac_acpkm_master(algo_class, encrypter, key_section_size, section_size, bs, data):
    """OMAC-ACPKM-Master

    :param algo_class: pygost.gost3412's algorithm class
    :param encrypter: encrypting function, that takes block as an input
    :param int key_section_size: ACPKM'es key section size (T*), in bytes
    :param int section_size: ACPKM'es section size (N), in bytes
    :param int bs: cipher's blocksize, bytes
    :param bytes data: data to authenticate
    """
    if len(data) % bs == 0:
        tail_offset = len(data) - bs
    else:
        tail_offset = len(data) - (len(data) % bs)
    prev = bs * b"\x00"
    sections = len(data) // section_size
    if len(data) % section_size != 0:
        sections += 1
    keymats = acpkm_master(
        algo_class,
        encrypter,
        key_section_size,
        bs,
        (KEYSIZE + bs) * sections,
    )
    for i in xrange(0, tail_offset, bs):
        if i % section_size == 0:
            keymat, keymats = keymats[:KEYSIZE + bs], keymats[KEYSIZE + bs:]
            key, k1 = keymat[:KEYSIZE], keymat[KEYSIZE:]
            encrypter = algo_class(key).encrypt
        prev = encrypter(strxor(data[i:i + bs], prev))
    tail = data[tail_offset:]
    if len(tail) == bs:
        key, k1 = keymats[:KEYSIZE], keymats[KEYSIZE:]
        encrypter = algo_class(key).encrypt
    k2 = long2bytes(bytes2long(k1) << 1, size=bs)
    if bytearray(k1)[0] & 0x80 != 0:
        k2 = strxor(k2, long2bytes(Rb128 if bs == 16 else Rb64, size=bs))
    return encrypter(strxor(
        strxor(pad3(tail, bs), prev),
        k1 if len(tail) == bs else k2,
    ))


def pad_iso10126(data, blocksize):
    """ISO 10126 padding

    Does not exist in 34.13, but added for convenience.
    It uses urandom call for getting the randomness.
    """
    pad_len = blocksize - len(data) % blocksize
    if pad_len == 0:
        pad_len = blocksize
    return b"".join((data, urandom(pad_len - 1), bytes((pad_len,))))


def unpad_iso10126(data, blocksize):
    """Unpad :py:func:`pygost.gost3413.pad_iso10126`
    """
    if len(data) % blocksize != 0:
        raise ValueError("Data length is not multiple of blocksize")
    pad_len = bytearray(data)[-1]
    if pad_len > blocksize:
        raise ValueError("Padding length is bigger than blocksize")
    return data[:-pad_len]
