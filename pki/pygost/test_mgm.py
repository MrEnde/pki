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

from os import urandom
from random import randint
from unittest import TestCase

from pygost.gost3412 import GOST3412Kuznechik
from pygost.gost3412 import GOST3412Magma
from pygost.gost3412 import KEYSIZE
from pygost.mgm import MGM
from pygost.mgm import nonce_prepare
from pygost.utils import hexdec


class TestVector(TestCase):
    def runTest(self):
        key = hexdec("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF")
        ad = hexdec("0202020202020202010101010101010104040404040404040303030303030303EA0505050505050505")
        plaintext = hexdec("1122334455667700FFEEDDCCBBAA998800112233445566778899AABBCCEEFF0A112233445566778899AABBCCEEFF0A002233445566778899AABBCCEEFF0A0011AABBCC")
        mgm = MGM(GOST3412Kuznechik(key).encrypt, GOST3412Kuznechik.blocksize)
        ciphertext = mgm.seal(plaintext[:16], plaintext, ad)
        self.assertSequenceEqual(ciphertext[:len(plaintext)], hexdec("A9757B8147956E9055B8A33DE89F42FC8075D2212BF9FD5BD3F7069AADC16B39497AB15915A6BA85936B5D0EA9F6851CC60C14D4D3F883D0AB94420695C76DEB2C7552"))
        self.assertSequenceEqual(ciphertext[len(plaintext):], hexdec("CF5D656F40C34F5C46E8BB0E29FCDB4C"))
        self.assertSequenceEqual(mgm.open(plaintext[:16], ciphertext, ad), plaintext)


class TestSymmetric(TestCase):
    def _itself(self, mgm, bs, tag_size):
        for _ in range(1000):
            nonce = nonce_prepare(urandom(bs))
            ad = urandom(randint(0, 20))
            pt = urandom(randint(0, 20))
            if len(ad) + len(pt) == 0:
                continue
            ct = mgm.seal(nonce, pt, ad)
            self.assertEqual(len(ct) - tag_size, len(pt))
            self.assertSequenceEqual(mgm.open(nonce, ct, ad), pt)

    def test_magma(self):
        for tag_size in (
                GOST3412Magma.blocksize,
                GOST3412Magma.blocksize - 2,
        ):
            mgm = MGM(
                GOST3412Magma(urandom(KEYSIZE)).encrypt,
                GOST3412Magma.blocksize,
                tag_size,
            )
            self._itself(mgm, GOST3412Magma.blocksize, tag_size)

    def test_kuznechik(self):
        for tag_size in (
                GOST3412Kuznechik.blocksize,
                GOST3412Kuznechik.blocksize - 2,
        ):
            mgm = MGM(
                GOST3412Kuznechik(urandom(KEYSIZE)).encrypt,
                GOST3412Kuznechik.blocksize,
                tag_size,
            )
            self._itself(mgm, GOST3412Kuznechik.blocksize, tag_size)
