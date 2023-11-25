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
from unittest import TestCase

from pygost.gost28147 import DEFAULT_SBOX
from pygost.gost3412 import GOST3412Kuznechik
from pygost.gost3412 import GOST3412Magma
from pygost.utils import hexdec
from pygost.wrap import kexp15
from pygost.wrap import kimp15
from pygost.wrap import unwrap_cryptopro
from pygost.wrap import unwrap_gost
from pygost.wrap import wrap_cryptopro
from pygost.wrap import wrap_gost


class WrapGostTest(TestCase):
    def test_symmetric(self):
        for sbox in (DEFAULT_SBOX, "id-tc26-gost-28147-param-Z"):
            for _ in range(1 << 8):
                kek = urandom(32)
                cek = urandom(32)
                ukm = urandom(8)
                wrapped = wrap_gost(ukm, kek, cek, sbox=sbox)
                unwrapped = unwrap_gost(kek, wrapped, sbox=sbox)
                self.assertSequenceEqual(unwrapped, cek)

    def test_invalid_length(self):
        with self.assertRaises(ValueError):
            unwrap_gost(urandom(32), urandom(41))
        with self.assertRaises(ValueError):
            unwrap_gost(urandom(32), urandom(45))


class WrapCryptoproTest(TestCase):
    def test_symmetric(self):
        for sbox in (DEFAULT_SBOX, "id-tc26-gost-28147-param-Z"):
            for _ in range(1 << 8):
                kek = urandom(32)
                cek = urandom(32)
                ukm = urandom(8)
                wrapped = wrap_cryptopro(ukm, kek, cek, sbox=sbox)
                unwrapped = unwrap_cryptopro(kek, wrapped, sbox=sbox)
                self.assertSequenceEqual(unwrapped, cek)


class TestVectorKExp15(TestCase):
    """Test vectors from Р 1323565.1.017-2018
    """
    key = hexdec("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF")
    key_enc = hexdec("202122232425262728292A2B2C2D2E2F38393A3B3C3D3E3F3031323334353637")
    key_mac = hexdec("08090A0B0C0D0E0F0001020304050607101112131415161718191A1B1C1D1E1F")

    def test_magma(self):
        iv = hexdec("67BED654")
        kexp = kexp15(
            GOST3412Magma(self.key_enc).encrypt,
            GOST3412Magma(self.key_mac).encrypt,
            GOST3412Magma.blocksize,
            self.key,
            iv,
        )
        self.assertSequenceEqual(kexp, hexdec("""
CF D5 A1 2D 5B 81 B6 E1 E9 9C 91 6D 07 90 0C 6A
C1 27 03 FB 3A BD ED 55 56 7B F3 74 2C 89 9C 75
5D AF E7 B4 2E 3A 8B D9
        """.replace("\n", "").replace(" ", "")))
        self.assertSequenceEqual(kimp15(
            GOST3412Magma(self.key_enc).encrypt,
            GOST3412Magma(self.key_mac).encrypt,
            GOST3412Magma.blocksize,
            kexp,
            iv,
        ), self.key)

    def test_kuznechik(self):
        iv = hexdec("0909472DD9F26BE8")
        kexp = kexp15(
            GOST3412Kuznechik(self.key_enc).encrypt,
            GOST3412Kuznechik(self.key_mac).encrypt,
            GOST3412Kuznechik.blocksize,
            self.key,
            iv,
        )
        self.assertSequenceEqual(kexp, hexdec("""
E3 61 84 E8 4E 8D 73 6F F3 6C C2 E5 AE 06 5D C6
56 B2 3C 20 F5 49 B0 2F DF F8 8E 1F 3F 30 D8 C2
9A 53 F3 CA 55 4D BA D8 0D E1 52 B9 A4 62 5B 32
        """.replace("\n", "").replace(" ", "")))
        self.assertSequenceEqual(kimp15(
            GOST3412Kuznechik(self.key_enc).encrypt,
            GOST3412Kuznechik(self.key_mac).encrypt,
            GOST3412Kuznechik.blocksize,
            kexp,
            iv,
        ), self.key)
