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
from pygost.gost3413 import _mac_ks
from pygost.gost3413 import acpkm
from pygost.gost3413 import acpkm_master
from pygost.gost3413 import cbc_decrypt
from pygost.gost3413 import cbc_encrypt
from pygost.gost3413 import cfb_decrypt
from pygost.gost3413 import cfb_encrypt
from pygost.gost3413 import ctr
from pygost.gost3413 import ctr_acpkm
from pygost.gost3413 import ecb_decrypt
from pygost.gost3413 import ecb_encrypt
from pygost.gost3413 import KEYSIZE
from pygost.gost3413 import mac
from pygost.gost3413 import mac_acpkm_master
from pygost.gost3413 import ofb
from pygost.gost3413 import pad2
from pygost.gost3413 import pad_iso10126
from pygost.gost3413 import unpad2
from pygost.gost3413 import unpad_iso10126
from pygost.utils import hexdec
from pygost.utils import hexenc
from pygost.utils import strxor


class Pad2Test(TestCase):
    def test_symmetric(self):
        for _ in range(100):
            for blocksize in (GOST3412Magma.blocksize, GOST3412Kuznechik.blocksize):
                data = urandom(randint(0, blocksize * 3))
                self.assertSequenceEqual(
                    unpad2(pad2(data, blocksize), blocksize),
                    data,
                )


class GOST3412KuznechikModesTest(TestCase):
    key = hexdec("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    ciph = GOST3412Kuznechik(key)
    plaintext = ""
    plaintext += "1122334455667700ffeeddccbbaa9988"
    plaintext += "00112233445566778899aabbcceeff0a"
    plaintext += "112233445566778899aabbcceeff0a00"
    plaintext += "2233445566778899aabbcceeff0a0011"
    iv = hexdec("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")

    def test_ecb_vectors(self):
        ciphtext = ""
        ciphtext += "7f679d90bebc24305a468d42b9d4edcd"
        ciphtext += "b429912c6e0032f9285452d76718d08b"
        ciphtext += "f0ca33549d247ceef3f5a5313bd4b157"
        ciphtext += "d0b09ccde830b9eb3a02c4c5aa8ada98"
        self.assertSequenceEqual(
            hexenc(ecb_encrypt(
                self.ciph.encrypt,
                GOST3412Kuznechik.blocksize,
                hexdec(self.plaintext),
            )),
            ciphtext,
        )
        self.assertSequenceEqual(
            hexenc(ecb_decrypt(
                self.ciph.decrypt,
                GOST3412Kuznechik.blocksize,
                hexdec(ciphtext),
            )),
            self.plaintext,
        )

    def test_ecb_symmetric(self):
        for _ in range(100):
            pt = pad2(urandom(randint(0, 16 * 2)), GOST3412Kuznechik.blocksize)
            ciph = GOST3412Kuznechik(urandom(KEYSIZE))
            ct = ecb_encrypt(ciph.encrypt, GOST3412Kuznechik.blocksize, pt)
            self.assertSequenceEqual(ecb_decrypt(
                ciph.decrypt,
                GOST3412Kuznechik.blocksize,
                ct,
            ), pt)

    def test_ctr_vectors(self):
        ciphtext = ""
        ciphtext += "f195d8bec10ed1dbd57b5fa240bda1b8"
        ciphtext += "85eee733f6a13e5df33ce4b33c45dee4"
        ciphtext += "a5eae88be6356ed3d5e877f13564a3a5"
        ciphtext += "cb91fab1f20cbab6d1c6d15820bdba73"
        iv = self.iv[:GOST3412Kuznechik.blocksize // 2]
        self.assertSequenceEqual(
            hexenc(ctr(
                self.ciph.encrypt,
                GOST3412Kuznechik.blocksize,
                hexdec(self.plaintext),
                iv,
            )),
            ciphtext,
        )
        self.assertSequenceEqual(
            hexenc(ctr(
                self.ciph.encrypt,
                GOST3412Kuznechik.blocksize,
                hexdec(ciphtext),
                iv,
            )),
            self.plaintext,
        )

    def test_ctr_symmetric(self):
        for _ in range(100):
            pt = urandom(randint(0, 16 * 2))
            iv = urandom(GOST3412Kuznechik.blocksize // 2)
            ciph = GOST3412Kuznechik(urandom(KEYSIZE))
            ct = ctr(ciph.encrypt, GOST3412Kuznechik.blocksize, pt, iv)
            self.assertSequenceEqual(ctr(
                ciph.encrypt,
                GOST3412Kuznechik.blocksize,
                ct,
                iv,
            ), pt)

    def test_ofb_vectors(self):
        ciphtext = ""
        ciphtext += "81800a59b1842b24ff1f795e897abd95"
        ciphtext += "ed5b47a7048cfab48fb521369d9326bf"
        ciphtext += "66a257ac3ca0b8b1c80fe7fc10288a13"
        ciphtext += "203ebbc066138660a0292243f6903150"
        self.assertSequenceEqual(
            hexenc(ofb(
                self.ciph.encrypt,
                GOST3412Kuznechik.blocksize,
                hexdec(self.plaintext),
                self.iv,
            )),
            ciphtext,
        )
        self.assertSequenceEqual(
            hexenc(ofb(
                self.ciph.encrypt,
                GOST3412Kuznechik.blocksize,
                hexdec(ciphtext),
                self.iv,
            )),
            self.plaintext,
        )

    def test_ofb_symmetric(self):
        for _ in range(100):
            pt = urandom(randint(0, 16 * 2))
            iv = urandom(GOST3412Kuznechik.blocksize * 2)
            ciph = GOST3412Kuznechik(urandom(KEYSIZE))
            ct = ofb(ciph.encrypt, GOST3412Kuznechik.blocksize, pt, iv)
            self.assertSequenceEqual(ofb(
                ciph.encrypt,
                GOST3412Kuznechik.blocksize,
                ct,
                iv,
            ), pt)

    def test_ofb_manual(self):
        iv = [urandom(GOST3412Kuznechik.blocksize) for _ in range(randint(2, 10))]
        pt = [
            urandom(GOST3412Kuznechik.blocksize)
            for _ in range(len(iv), len(iv) + randint(1, 10))
        ]
        ciph = GOST3412Kuznechik(urandom(KEYSIZE))
        r = [ciph.encrypt(i) for i in iv]
        for i in range(len(pt) - len(iv)):
            r.append(ciph.encrypt(r[i]))
        ct = [strxor(g, r) for g, r in zip(pt, r)]
        self.assertSequenceEqual(
            ofb(ciph.encrypt, GOST3412Kuznechik.blocksize, b"".join(pt), b"".join(iv)),
            b"".join(ct),
        )

    def test_cbc_vectors(self):
        ciphtext = ""
        ciphtext += "689972d4a085fa4d90e52e3d6d7dcc27"
        ciphtext += "2826e661b478eca6af1e8e448d5ea5ac"
        ciphtext += "fe7babf1e91999e85640e8b0f49d90d0"
        ciphtext += "167688065a895c631a2d9a1560b63970"
        self.assertSequenceEqual(
            hexenc(cbc_encrypt(
                self.ciph.encrypt,
                GOST3412Kuznechik.blocksize,
                hexdec(self.plaintext),
                self.iv,
            )),
            ciphtext,
        )
        self.assertSequenceEqual(
            hexenc(cbc_decrypt(
                self.ciph.decrypt,
                GOST3412Kuznechik.blocksize,
                hexdec(ciphtext),
                self.iv,
            )),
            self.plaintext,
        )

    def test_cbc_symmetric(self):
        for _ in range(100):
            pt = pad2(urandom(randint(0, 16 * 2)), GOST3412Kuznechik.blocksize)
            iv = urandom(GOST3412Kuznechik.blocksize * 2)
            ciph = GOST3412Kuznechik(urandom(KEYSIZE))
            ct = cbc_encrypt(ciph.encrypt, GOST3412Kuznechik.blocksize, pt, iv)
            self.assertSequenceEqual(cbc_decrypt(
                ciph.decrypt,
                GOST3412Kuznechik.blocksize,
                ct,
                iv,
            ), pt)

    def test_cfb_vectors(self):
        ciphtext = ""
        ciphtext += "81800a59b1842b24ff1f795e897abd95"
        ciphtext += "ed5b47a7048cfab48fb521369d9326bf"
        ciphtext += "79f2a8eb5cc68d38842d264e97a238b5"
        ciphtext += "4ffebecd4e922de6c75bd9dd44fbf4d1"
        self.assertSequenceEqual(
            hexenc(cfb_encrypt(
                self.ciph.encrypt,
                GOST3412Kuznechik.blocksize,
                hexdec(self.plaintext),
                self.iv,
            )),
            ciphtext,
        )
        self.assertSequenceEqual(
            hexenc(cfb_decrypt(
                self.ciph.encrypt,
                GOST3412Kuznechik.blocksize,
                hexdec(ciphtext),
                self.iv,
            )),
            self.plaintext,
        )

    def test_cfb_symmetric(self):
        for _ in range(100):
            pt = urandom(randint(0, 16 * 2))
            iv = urandom(GOST3412Kuznechik.blocksize * 2)
            ciph = GOST3412Kuznechik(urandom(KEYSIZE))
            ct = cfb_encrypt(ciph.encrypt, GOST3412Kuznechik.blocksize, pt, iv)
            self.assertSequenceEqual(cfb_decrypt(
                ciph.encrypt,
                GOST3412Kuznechik.blocksize,
                ct,
                iv,
            ), pt)

    def test_mac_vectors(self):
        k1, k2 = _mac_ks(self.ciph.encrypt, GOST3412Kuznechik.blocksize)
        self.assertSequenceEqual(hexenc(k1), "297d82bc4d39e3ca0de0573298151dc7")
        self.assertSequenceEqual(hexenc(k2), "52fb05789a73c7941bc0ae65302a3b8e")
        self.assertSequenceEqual(
            hexenc(mac(
                self.ciph.encrypt,
                GOST3412Kuznechik.blocksize,
                hexdec(self.plaintext),
            )[:8]),
            "336f4d296059fbe3",
        )

    def test_mac_applies(self):
        for _ in range(100):
            data = urandom(randint(0, 16 * 2))
            ciph = GOST3412Kuznechik(urandom(KEYSIZE))
            mac(ciph.encrypt, GOST3412Kuznechik.blocksize, data)


class GOST3412MagmaModesTest(TestCase):
    key = hexdec("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    ciph = GOST3412Magma(key)
    plaintext = ""
    plaintext += "92def06b3c130a59"
    plaintext += "db54c704f8189d20"
    plaintext += "4a98fb2e67a8024c"
    plaintext += "8912409b17b57e41"
    iv = hexdec("1234567890abcdef234567890abcdef134567890abcdef12")

    def test_ecb_vectors(self):
        ciphtext = ""
        ciphtext += "2b073f0494f372a0"
        ciphtext += "de70e715d3556e48"
        ciphtext += "11d8d9e9eacfbc1e"
        ciphtext += "7c68260996c67efb"
        self.assertSequenceEqual(
            hexenc(ecb_encrypt(
                self.ciph.encrypt,
                GOST3412Magma.blocksize,
                hexdec(self.plaintext),
            )),
            ciphtext,
        )
        self.assertSequenceEqual(
            hexenc(ecb_decrypt(
                self.ciph.decrypt,
                GOST3412Magma.blocksize,
                hexdec(ciphtext),
            )),
            self.plaintext,
        )

    def test_ecb_symmetric(self):
        for _ in range(100):
            pt = pad2(urandom(randint(0, 16 * 2)), 16)
            ciph = GOST3412Magma(urandom(KEYSIZE))
            ct = ecb_encrypt(ciph.encrypt, GOST3412Magma.blocksize, pt)
            self.assertSequenceEqual(ecb_decrypt(
                ciph.decrypt,
                GOST3412Magma.blocksize,
                ct,
            ), pt)

    def test_ctr_vectors(self):
        ciphtext = ""
        ciphtext += "4e98110c97b7b93c"
        ciphtext += "3e250d93d6e85d69"
        ciphtext += "136d868807b2dbef"
        ciphtext += "568eb680ab52a12d"
        iv = self.iv[:4]
        self.assertSequenceEqual(
            hexenc(ctr(
                self.ciph.encrypt,
                GOST3412Magma.blocksize,
                hexdec(self.plaintext),
                iv,
            )),
            ciphtext,
        )
        self.assertSequenceEqual(
            hexenc(ctr(
                self.ciph.encrypt,
                GOST3412Magma.blocksize,
                hexdec(ciphtext),
                iv,
            )),
            self.plaintext,
        )

    def test_ctr_symmetric(self):
        for _ in range(100):
            pt = urandom(randint(0, 16 * 2))
            iv = urandom(GOST3412Magma.blocksize // 2)
            ciph = GOST3412Magma(urandom(KEYSIZE))
            ct = ctr(ciph.encrypt, GOST3412Magma.blocksize, pt, iv)
            self.assertSequenceEqual(ctr(
                ciph.encrypt,
                GOST3412Magma.blocksize,
                ct,
                iv,
            ), pt)

    def test_ofb_vectors(self):
        iv = self.iv[:16]
        ciphtext = ""
        ciphtext += "db37e0e266903c83"
        ciphtext += "0d46644c1f9a089c"
        ciphtext += "a0f83062430e327e"
        ciphtext += "c824efb8bd4fdb05"
        self.assertSequenceEqual(
            hexenc(ofb(
                self.ciph.encrypt,
                GOST3412Magma.blocksize,
                hexdec(self.plaintext),
                iv,
            )),
            ciphtext,
        )
        self.assertSequenceEqual(
            hexenc(ofb(
                self.ciph.encrypt,
                GOST3412Magma.blocksize,
                hexdec(ciphtext),
                iv,
            )),
            self.plaintext,
        )

    def test_ofb_symmetric(self):
        for _ in range(100):
            pt = urandom(randint(0, 16 * 2))
            iv = urandom(GOST3412Magma.blocksize * 2)
            ciph = GOST3412Magma(urandom(KEYSIZE))
            ct = ofb(ciph.encrypt, GOST3412Magma.blocksize, pt, iv)
            self.assertSequenceEqual(ofb(
                ciph.encrypt,
                GOST3412Magma.blocksize,
                ct,
                iv,
            ), pt)

    def test_cbc_vectors(self):
        ciphtext = ""
        ciphtext += "96d1b05eea683919"
        ciphtext += "aff76129abb937b9"
        ciphtext += "5058b4a1c4bc0019"
        ciphtext += "20b78b1a7cd7e667"
        self.assertSequenceEqual(
            hexenc(cbc_encrypt(
                self.ciph.encrypt,
                GOST3412Magma.blocksize,
                hexdec(self.plaintext),
                self.iv,
            )),
            ciphtext,
        )
        self.assertSequenceEqual(
            hexenc(cbc_decrypt(
                self.ciph.decrypt,
                GOST3412Magma.blocksize,
                hexdec(ciphtext),
                self.iv,
            )),
            self.plaintext,
        )

    def test_cbc_symmetric(self):
        for _ in range(100):
            pt = pad2(urandom(randint(0, 16 * 2)), 16)
            iv = urandom(GOST3412Magma.blocksize * 2)
            ciph = GOST3412Magma(urandom(KEYSIZE))
            ct = cbc_encrypt(ciph.encrypt, GOST3412Magma.blocksize, pt, iv)
            self.assertSequenceEqual(cbc_decrypt(
                ciph.decrypt,
                GOST3412Magma.blocksize,
                ct,
                iv,
            ), pt)

    def test_cfb_vectors(self):
        iv = self.iv[:16]
        ciphtext = ""
        ciphtext += "db37e0e266903c83"
        ciphtext += "0d46644c1f9a089c"
        ciphtext += "24bdd2035315d38b"
        ciphtext += "bcc0321421075505"
        self.assertSequenceEqual(
            hexenc(cfb_encrypt(
                self.ciph.encrypt,
                GOST3412Magma.blocksize,
                hexdec(self.plaintext),
                iv,
            )),
            ciphtext,
        )
        self.assertSequenceEqual(
            hexenc(cfb_decrypt(
                self.ciph.encrypt,
                GOST3412Magma.blocksize,
                hexdec(ciphtext),
                iv,
            )),
            self.plaintext,
        )

    def test_cfb_symmetric(self):
        for _ in range(100):
            pt = urandom(randint(0, 16 * 2))
            iv = urandom(GOST3412Magma.blocksize * 2)
            ciph = GOST3412Magma(urandom(KEYSIZE))
            ct = cfb_encrypt(ciph.encrypt, GOST3412Magma.blocksize, pt, iv)
            self.assertSequenceEqual(cfb_decrypt(
                ciph.encrypt,
                GOST3412Magma.blocksize,
                ct,
                iv,
            ), pt)

    def test_mac_vectors(self):
        k1, k2 = _mac_ks(self.ciph.encrypt, GOST3412Magma.blocksize)
        self.assertSequenceEqual(hexenc(k1), "5f459b3342521424")
        self.assertSequenceEqual(hexenc(k2), "be8b366684a42848")
        self.assertSequenceEqual(
            hexenc(mac(
                self.ciph.encrypt,
                GOST3412Magma.blocksize,
                hexdec(self.plaintext),
            )[:4]),
            "154e7210",
        )

    def test_mac_applies(self):
        for _ in range(100):
            data = urandom(randint(0, 16 * 2))
            ciph = GOST3412Magma(urandom(KEYSIZE))
            mac(ciph.encrypt, GOST3412Magma.blocksize, data)


class TestVectorACPKM(TestCase):
    """Test vectors from Р 1323565.1.017-2018
    """
    key = hexdec("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF")

    def test_magma_ctr_acpkm(self):
        key = acpkm(GOST3412Magma(self.key).encrypt, GOST3412Magma.blocksize)
        self.assertSequenceEqual(key, hexdec("863EA017842C3D372B18A85A28E2317D74BEFC107720DE0C9E8AB974ABD00CA0"))
        key = acpkm(GOST3412Magma(key).encrypt, GOST3412Magma.blocksize)
        self.assertSequenceEqual(key, hexdec("49A5E2677DE555982B8AD5E826652D17EEC847BF5B3997A81CF7FE7F1187BD27"))
        key = acpkm(GOST3412Magma(key).encrypt, GOST3412Magma.blocksize)
        self.assertSequenceEqual(key, hexdec("3256BF3F97B5667426A9FB1C5EAABE41893CCDD5A868F9B63B0AA90720FA43C4"))

    def test_magma_ctr(self):
        encrypter = GOST3412Magma(self.key).encrypt
        plaintext = hexdec("""
11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88
00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A
11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00
22 33 44 55 66 77 88 99
        """.replace("\n", "").replace(" ", ""))
        iv = hexdec("12345678")
        ciphertext = hexdec("""
2A B8 1D EE EB 1E 4C AB 68 E1 04 C4 BD 6B 94 EA
C7 2C 67 AF 6C 2E 5B 6B 0E AF B6 17 70 F1 B3 2E
A1 AE 71 14 9E ED 13 82 AB D4 67 18 06 72 EC 6F
84 A2 F1 5B 3F CA 72 C1
        """.replace("\n", "").replace(" ", ""))
        self.assertSequenceEqual(
            ctr_acpkm(
                GOST3412Magma,
                encrypter,
                bs=GOST3412Magma.blocksize,
                section_size=GOST3412Magma.blocksize * 2,
                data=plaintext,
                iv=iv
            ),
            ciphertext,
        )
        self.assertSequenceEqual(
            ctr_acpkm(
                GOST3412Magma,
                encrypter,
                bs=GOST3412Magma.blocksize,
                section_size=GOST3412Magma.blocksize * 2,
                data=ciphertext,
                iv=iv
            ),
            plaintext,
        )

    def test_kuznechik_ctr_acpkm(self):
        key = acpkm(GOST3412Kuznechik(self.key).encrypt, GOST3412Kuznechik.blocksize)
        self.assertSequenceEqual(key, hexdec("2666ED40AE687811745CA0B448F57A7B390ADB5780307E8E9659AC403AE60C60"))
        key = acpkm(GOST3412Kuznechik(key).encrypt, GOST3412Kuznechik.blocksize)
        self.assertSequenceEqual(key, hexdec("BB3DD5402E999B7A3DEBB0DB45448EC530F07365DFEE3ABA8415F77AC8F34CE8"))
        key = acpkm(GOST3412Kuznechik(key).encrypt, GOST3412Kuznechik.blocksize)
        self.assertSequenceEqual(key, hexdec("23362FD553CAD2178299A5B5A2D4722E3BB83C730A8BF57CE2DD004017F8C565"))

    def test_kuznechik_ctr(self):
        encrypter = GOST3412Kuznechik(self.key).encrypt
        iv = hexdec("1234567890ABCEF0")
        plaintext = hexdec("""
11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88
00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A
11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00
22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11
33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 22
44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 22 33
55 66 77 88 99 AA BB CC EE FF 0A 00 11 22 33 44
        """.replace("\n", "").replace(" ", ""))
        ciphertext = hexdec("""
F1 95 D8 BE C1 0E D1 DB D5 7B 5F A2 40 BD A1 B8
85 EE E7 33 F6 A1 3E 5D F3 3C E4 B3 3C 45 DE E4
4B CE EB 8F 64 6F 4C 55 00 17 06 27 5E 85 E8 00
58 7C 4D F5 68 D0 94 39 3E 48 34 AF D0 80 50 46
CF 30 F5 76 86 AE EC E1 1C FC 6C 31 6B 8A 89 6E
DF FD 07 EC 81 36 36 46 0C 4F 3B 74 34 23 16 3E
64 09 A9 C2 82 FA C8 D4 69 D2 21 E7 FB D6 DE 5D
        """.replace("\n", "").replace(" ", ""))
        self.assertSequenceEqual(
            ctr_acpkm(
                GOST3412Kuznechik,
                encrypter,
                bs=GOST3412Kuznechik.blocksize,
                section_size=GOST3412Kuznechik.blocksize * 2,
                data=plaintext,
                iv=iv,
            ),
            ciphertext,
        )
        self.assertSequenceEqual(
            ctr_acpkm(
                GOST3412Kuznechik,
                encrypter,
                bs=GOST3412Kuznechik.blocksize,
                section_size=GOST3412Kuznechik.blocksize * 2,
                data=ciphertext,
                iv=iv,
            ),
            plaintext,
        )

    def test_magma_omac_1_5_blocks(self):
        encrypter = GOST3412Magma(self.key).encrypt
        key_section_size = 640 // 8
        self.assertSequenceEqual(
            acpkm_master(
                GOST3412Magma,
                encrypter,
                key_section_size=key_section_size,
                bs=GOST3412Magma.blocksize,
                keymat_len=KEYSIZE + GOST3412Magma.blocksize,
            ),
            hexdec("0DF2F5273DA328932AC49D81D36B2558A50DBF9BBCAC74A614B2CCB2F1CBCD8A70638E3DE8B3571E"),
        )
        text = hexdec("1122334455667700FFEEDDCC")
        self.assertSequenceEqual(
            mac_acpkm_master(
                GOST3412Magma,
                encrypter,
                key_section_size,
                section_size=GOST3412Magma.blocksize * 2,
                bs=GOST3412Magma.blocksize,
                data=text,
            ),
            hexdec("A0540E3730ACBCF3"),
        )

    def test_magma_omac_5_blocks(self):
        encrypter = GOST3412Magma(self.key).encrypt
        key_section_size = 640 // 8
        self.assertSequenceEqual(
            acpkm_master(
                GOST3412Magma,
                encrypter,
                key_section_size=key_section_size,
                bs=GOST3412Magma.blocksize,
                keymat_len=3 * (KEYSIZE + GOST3412Magma.blocksize),
            ),
            hexdec("""
0D F2 F5 27 3D A3 28 93 2A C4 9D 81 D3 6B 25 58
A5 0D BF 9B BC AC 74 A6 14 B2 CC B2 F1 CB CD 8A
70 63 8E 3D E8 B3 57 1E 8D 38 26 D5 5E 63 A1 67
E2 40 66 40 54 7B 9F 1F 5F 2B 43 61 2A AE AF DA
18 0B AC 86 04 DF A6 FE 53 C2 CE 27 0E 9C 9F 52
68 D0 FD BF E1 A3 BD D9 BE 5B 96 D0 A1 20 23 48
6E F1 71 0F 92 4A E0 31 30 52 CB 5F CA 0B 79 1E
1B AB E8 57 6D 0F E3 A8
            """.replace("\n", "").replace(" ", "")),
        )
        text = hexdec("""
11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88
00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A
11 22 33 44 55 66 77 88
        """.replace("\n", "").replace(" ", ""))
        self.assertSequenceEqual(
            mac_acpkm_master(
                GOST3412Magma,
                encrypter,
                key_section_size,
                section_size=GOST3412Magma.blocksize * 2,
                bs=GOST3412Magma.blocksize,
                data=text,
            ),
            hexdec("34008DAD5496BB8E"),
        )

    def test_kuznechik_omac_1_5_blocks(self):
        encrypter = GOST3412Kuznechik(self.key).encrypt
        key_section_size = 768 // 8
        self.assertSequenceEqual(
            acpkm_master(
                GOST3412Kuznechik,
                encrypter,
                key_section_size=key_section_size,
                bs=GOST3412Kuznechik.blocksize,
                keymat_len=KEYSIZE + GOST3412Kuznechik.blocksize,
            ),
            hexdec("""
0C AB F1 F2 EF BC 4A C1 60 48 DF 1A 24 C6 05 B2
C0 D1 67 3D 75 86 A8 EC 0D D4 2C 45 A4 F9 5B AE
0F 2E 26 17 E4 71 48 68 0F C3 E6 17 8D F2 C1 37
            """.replace("\n", "").replace(" ", ""))
        )
        text = hexdec("""
11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88
00 11 22 33 44 55 66 77
        """.replace("\n", "").replace(" ", ""))
        self.assertSequenceEqual(
            mac_acpkm_master(
                GOST3412Kuznechik,
                encrypter,
                key_section_size,
                section_size=GOST3412Kuznechik.blocksize * 2,
                bs=GOST3412Kuznechik.blocksize,
                data=text,
            ),
            hexdec("B5367F47B62B995EEB2A648C5843145E"),
        )

    def test_kuznechik_omac_5_blocks(self):
        encrypter = GOST3412Kuznechik(self.key).encrypt
        key_section_size = 768 // 8
        self.assertSequenceEqual(
            acpkm_master(
                GOST3412Kuznechik,
                encrypter,
                key_section_size=key_section_size,
                bs=GOST3412Kuznechik.blocksize,
                keymat_len=3 * (KEYSIZE + GOST3412Kuznechik.blocksize),
            ),
            hexdec("""
0C AB F1 F2 EF BC 4A C1 60 48 DF 1A 24 C6 05 B2
C0 D1 67 3D 75 86 A8 EC 0D D4 2C 45 A4 F9 5B AE
0F 2E 26 17 E4 71 48 68 0F C3 E6 17 8D F2 C1 37
C9 DD A8 9C FF A4 91 FE AD D9 B3 EA B7 03 BB 31
BC 7E 92 7F 04 94 72 9F 51 B4 9D 3D F9 C9 46 08
00 FB BC F5 ED EE 61 0E A0 2F 01 09 3C 7B C7 42
D7 D6 27 15 01 B1 77 77 52 63 C2 A3 49 5A 83 18
A8 1C 79 A0 4F 29 66 0E A3 FD A8 74 C6 30 79 9E
14 2C 57 79 14 FE A9 0D 3B C2 50 2E 83 36 85 D9
            """.replace("\n", "").replace(" ", "")),
        )
        text = hexdec("""
11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88
00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A
11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00
22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11
33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 22
        """.replace("\n", "").replace(" ", ""))
        self.assertSequenceEqual(
            mac_acpkm_master(
                GOST3412Kuznechik,
                encrypter,
                key_section_size,
                section_size=GOST3412Kuznechik.blocksize * 2,
                bs=GOST3412Kuznechik.blocksize,
                data=text,
            ),
            hexdec("FBB8DCEE45BEA67C35F58C5700898E5D"),
        )


class ISO10126Test(TestCase):
    def test_symmetric(self):
        for _ in range(100):
            for blocksize in (GOST3412Magma.blocksize, GOST3412Kuznechik.blocksize):
                data = urandom(randint(0, blocksize * 3))
                padded = pad_iso10126(data, blocksize)
                self.assertSequenceEqual(unpad_iso10126(padded, blocksize), data)
                with self.assertRaises(ValueError):
                    unpad_iso10126(padded[1:], blocksize)

    def test_small(self):
        with self.assertRaises(ValueError):
            unpad_iso10126(b"foobar\x00\x09", 8)
