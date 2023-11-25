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

from unittest import TestCase

from pygost.kdf import kdf_gostr3411_2012_256
from pygost.kdf import kdf_tree_gostr3411_2012_256
from pygost.utils import hexdec


class TestKDFGOSTR34112012256(TestCase):
    def runTest(self):
        self.assertEqual(
            kdf_gostr3411_2012_256(
                hexdec("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                hexdec("26bdb878"),
                hexdec("af21434145656378"),
            ),
            hexdec("a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"),
        )


class TestKDFTREEGOSTR34112012256(TestCase):
    def runTest(self):
        self.assertSequenceEqual(
            kdf_tree_gostr3411_2012_256(
                hexdec("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                hexdec("26bdb878"),
                hexdec("af21434145656378"),
                1,
            ),
            (hexdec("a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"),),
        )
        self.assertSequenceEqual(
            kdf_tree_gostr3411_2012_256(
                hexdec("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                hexdec("26bdb878"),
                hexdec("af21434145656378"),
                2,
            ),
            (
                hexdec("22b6837845c6bef65ea71672b265831086d3c76aebe6dae91cad51d83f79d16b"),
                hexdec("074c9330599d7f8d712fca54392f4ddde93751206b3584c8f43f9e6dc51531f9"),
            ),
        )
