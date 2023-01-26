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
"""Multilinear Galois Mode (MGM) block cipher mode.
"""

from hmac import compare_digest

from pygost.gost3413 import pad1
from pygost.utils import bytes2long
from pygost.utils import long2bytes
from pygost.utils import strxor


def _incr(data, bs):
    return long2bytes(bytes2long(data) + 1, size=bs // 2)


def incr_r(data, bs):
    return data[:bs // 2] + _incr(data[bs // 2:], bs)


def incr_l(data, bs):
    return _incr(data[:bs // 2], bs) + data[bs // 2:]


def nonce_prepare(nonce):
    """Prepare nonce for MGM usage

    It just clears MSB.
    """
    n = bytearray(nonce)
    n[0] &= 0x7F
    return bytes(n)


class MGM(object):
    # Implementation is fully based on go.cypherpunks.ru/gogost/mgm
    def __init__(self, encrypter, bs, tag_size=None):
        """Multilinear Galois Mode (MGM) block cipher mode

        :param encrypter: encrypting function, that takes block as an input
        :param int bs: cipher's blocksize
        :param int tag_size: authentication tag size
                             (defaults to blocksize if not specified)
        """
        if bs not in (8, 16):
            raise ValueError("Only 64/128-bit blocksizes allowed")
        self.tag_size = bs if tag_size is None else tag_size
        if self.tag_size < 4 or self.tag_size > bs:
            raise ValueError("Invalid tag_size")
        self.encrypter = encrypter
        self.bs = bs
        self.max_size = (1 << (bs * 8 // 2)) - 1
        self.r = 0x1B if bs == 8 else 0x87

    def _validate_nonce(self, nonce):
        if len(nonce) != self.bs:
            raise ValueError("nonce length must be equal to cipher's blocksize")
        if bytearray(nonce)[0] & 0x80 > 0:
            raise ValueError("nonce must not have higher bit set")

    def _validate_sizes(self, plaintext, additional_data):
        if len(plaintext) == 0 and len(additional_data) == 0:
            raise ValueError("At least one of plaintext or additional_data required")
        if len(plaintext) + len(additional_data) > self.max_size:
            raise ValueError("plaintext+additional_data are too big")

    def _mul(self, x, y):
        x = bytes2long(x)
        y = bytes2long(y)
        z = 0
        max_bit = 1 << (self.bs * 8 - 1)
        while y > 0:
            if y & 1 == 1:
                z ^= x
            if x & max_bit > 0:
                x = ((x ^ max_bit) << 1) ^ self.r
            else:
                x <<= 1
            y >>= 1
        return long2bytes(z, size=self.bs)

    def _crypt(self, icn, data):
        icn[0] &= 0x7F
        enc = self.encrypter(bytes(icn))
        res = []
        while len(data) > 0:
            res.append(strxor(self.encrypter(enc), data))
            enc = incr_r(enc, self.bs)
            data = data[self.bs:]
        return b"".join(res)

    def _auth(self, icn, text, ad):
        icn[0] |= 0x80
        enc = self.encrypter(bytes(icn))
        _sum = self.bs * b"\x00"
        ad_len = len(ad)
        text_len = len(text)
        while len(ad) > 0:
            _sum = strxor(_sum, self._mul(
                self.encrypter(enc),
                pad1(ad[:self.bs], self.bs),
            ))
            enc = incr_l(enc, self.bs)
            ad = ad[self.bs:]
        while len(text) > 0:
            _sum = strxor(_sum, self._mul(
                self.encrypter(enc),
                pad1(text[:self.bs], self.bs),
            ))
            enc = incr_l(enc, self.bs)
            text = text[self.bs:]
        _sum = strxor(_sum, self._mul(self.encrypter(enc), (
            long2bytes(ad_len * 8, size=self.bs // 2) +
            long2bytes(text_len * 8, size=self.bs // 2)
        )))
        return self.encrypter(_sum)[:self.tag_size]

    def seal(self, nonce, plaintext, additional_data):
        """Seal plaintext

        :param bytes nonce: blocksize-sized nonce.
                            Assure that it does not have MSB bit set
                            (:py:func:`pygost.mgm.nonce_prepare` helps)
        :param bytes plaintext: plaintext to be encrypted and authenticated
        :param bytes additional_data: additional data to be authenticated
        """
        self._validate_nonce(nonce)
        self._validate_sizes(plaintext, additional_data)
        icn = bytearray(nonce)
        ciphertext = self._crypt(icn, plaintext)
        tag = self._auth(icn, ciphertext, additional_data)
        return ciphertext + tag

    def open(self, nonce, ciphertext, additional_data):
        """Open ciphertext

        :param bytes nonce: blocksize-sized nonce.
                            Assure that it does not have MSB bit set
                            (:py:func:`pygost.mgm.nonce_prepare` helps)
        :param bytes ciphertext: ciphertext to be decrypted and authenticated
        :param bytes additional_data: additional data to be authenticated
        :raises ValueError: if ciphertext authentication fails
        """
        self._validate_nonce(nonce)
        self._validate_sizes(ciphertext, additional_data)
        icn = bytearray(nonce)
        ciphertext, tag_expected = (
            ciphertext[:-self.tag_size],
            ciphertext[-self.tag_size:],
        )
        tag = self._auth(icn, ciphertext, additional_data)
        if not compare_digest(tag_expected, tag):
            raise ValueError("Invalid authentication tag")
        return self._crypt(icn, ciphertext)
