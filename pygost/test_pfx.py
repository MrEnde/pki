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

from base64 import b64decode
from hmac import new as hmac_new
from unittest import skipIf
from unittest import TestCase

from pygost import gost3410
from pygost.gost28147 import cfb_decrypt
from pygost.gost34112012256 import GOST34112012256
from pygost.gost34112012512 import GOST34112012512
from pygost.gost34112012512 import pbkdf2 as gost34112012_pbkdf2
from pygost.gost3412 import GOST3412Kuznechik
from pygost.gost3412 import GOST3412Magma
from pygost.gost3412 import KEYSIZE
from pygost.gost3413 import ctr_acpkm
from pygost.gost3413 import mac as omac
from pygost.kdf import kdf_tree_gostr3411_2012_256
from pygost.kdf import keg
from pygost.utils import hexdec
from pygost.wrap import kimp15


try:
    from pyderasn import OctetString

    from pygost.asn1schemas.cms import EncryptedData
    from pygost.asn1schemas.cms import EnvelopedData
    from pygost.asn1schemas.cms import SignedAttributes
    from pygost.asn1schemas.cms import SignedData
    from pygost.asn1schemas.oids import id_data
    from pygost.asn1schemas.oids import id_envelopedData
    from pygost.asn1schemas.oids import id_gostr3412_2015_kuznyechik_ctracpkm
    from pygost.asn1schemas.oids import id_gostr3412_2015_kuznyechik_wrap_kexp15
    from pygost.asn1schemas.oids import id_messageDigest
    from pygost.asn1schemas.oids import id_pbes2
    from pygost.asn1schemas.oids import id_pkcs12_bagtypes_certBag
    from pygost.asn1schemas.oids import id_pkcs12_bagtypes_keyBag
    from pygost.asn1schemas.oids import id_pkcs12_bagtypes_pkcs8ShroudedKeyBag
    from pygost.asn1schemas.oids import id_pkcs9_certTypes_x509Certificate
    from pygost.asn1schemas.oids import id_signedData
    from pygost.asn1schemas.oids import id_tc26_agreement_gost3410_2012_256
    from pygost.asn1schemas.oids import id_tc26_gost3411_2012_256
    from pygost.asn1schemas.pfx import CertBag
    from pygost.asn1schemas.pfx import KeyBag
    from pygost.asn1schemas.pfx import OctetStringSafeContents
    from pygost.asn1schemas.pfx import PBES2Params
    from pygost.asn1schemas.pfx import PFX
    from pygost.asn1schemas.pfx import PKCS8ShroudedKeyBag
    from pygost.asn1schemas.pfx import SafeContents
    from pygost.asn1schemas.x509 import Certificate
except ImportError:
    pyderasn_exists = False
else:
    pyderasn_exists = True


@skipIf(not pyderasn_exists, "PyDERASN dependency is required")
class TestPFX(TestCase):
    """PFX test vectors from "Транспортный ключевой контейнер" (R50.1.112-2016.pdf)
    """
    pfx_raw = b64decode("""
MIIFqgIBAzCCBSsGCSqGSIb3DQEHAaCCBRwEggUYMIIFFDCCASIGCSqGSIb3DQEH
AaCCARMEggEPMIIBCzCCAQcGCyqGSIb3DQEMCgECoIHgMIHdMHEGCSqGSIb3DQEF
DTBkMEEGCSqGSIb3DQEFDDA0BCD5qZr0TTIsBvdgUoq/zFwOzdyJohj6/4Wiyccg
j9AK/QICB9AwDAYIKoUDBwEBBAIFADAfBgYqhQMCAhUwFQQI3Ip/Vp0IsyIGCSqF
AwcBAgUBAQRoSfLhgx9s/zn+BjnhT0ror07vS55Ys5hgvVpWDx4mXGWWyez/2sMc
aFgSr4H4UTGGwoMynGLpF1IOVo+bGJ0ePqHB+gS5OL9oV+PUmZ/ELrRENKlCDqfY
WvpSystX29CvCFrnTnDsbBYxFTATBgkqhkiG9w0BCRUxBgQEAQAAADCCA+oGCSqG
SIb3DQEHBqCCA9swggPXAgEAMIID0AYJKoZIhvcNAQcBMHEGCSqGSIb3DQEFDTBk
MEEGCSqGSIb3DQEFDDA0BCCJTJLZQRi1WIpQHzyjXbq7+Vw2+1280C45x8ff6kMS
VAICB9AwDAYIKoUDBwEBBAIFADAfBgYqhQMCAhUwFQQIxepowwvS11MGCSqFAwcB
AgUBAYCCA06n09P/o+eDEKoSWpvlpOLKs7dKmVquKzJ81nCngvLQ5fEWL1WkxwiI
rEhm53JKLD0wy4hekalEk011Bvc51XP9gkDkmaoBpnV/TyKIY35wl6ATfeGXno1M
KoA+Ktdhv4gLnz0k2SXdkUj11JwYskXue+REA0p4m2ZsoaTmvoODamh9JeY/5Qjy
Xe58CGnyXFzX3eU86qs4WfdWdS3NzYYOk9zzVl46le9u79O/LnW2j4n2of/Jpk/L
YjrRmz5oYeQOqKOKhEyhpO6e+ejr6laduEv7TwJQKRNiygogbVvkNn3VjHTSOUG4
W+3NRPhjb0jD9obdyx6MWa6O3B9bUzFMNav8/gYn0vTDxqXMLy/92oTngNrVx6Gc
cNl128ISrDS6+RxtAMiEBRK6xNkemqX5yNXG5GrLQQFGP6mbs2nNpjKlgj3pljmX
Eky2/G78XiJrv02OgGs6CKnI9nMpa6N7PBHV34MJ6EZzWOWDRQ420xk63mnicrs0
WDVJ0xjdu4FW3iEk02EaiRTvGBpa6GL7LBp6QlaXSSwONx725cyRsL9cTlukqXER
WHDlMpjYLbkGZRrCc1myWgEfsputfSIPNF/oLv9kJNWacP3uuDOfecg3us7eg2OA
xo5zrYfn39GcBMF1WHAYRO/+PnJb9jrDuLAE8+ONNqjNulWNK9CStEhb6Te+yE6q
oeP6hJjFLi+nFLE9ymIo0A7gLQD5vzFvl+7v1ZNVnQkwRUsWoRiEVVGnv3Z1iZU6
xStxgoHMl62V/P5cz4dr9vJM2adEWNZcVXl6mk1H8DRc1sRGnvs2l237oKWRVntJ
hoWnZ8qtD+3ZUqsX79QhVzUQBzKuBt6jwNhaHLGl5B+Or/zA9FezsOh6+Uc+fZaV
W7fFfeUyWwGy90XD3ybTrjzep9f3nt55Z2c+fu2iEwhoyImWLuC3+CVhf9Af59j9
8/BophMJuATDJEtgi8rt4vLnfxKu250Mv2ZpbfF69EGTgFYbwc55zRfaUG9zlyCu
1YwMJ6HC9FUVtJp9gObSrirbzTH7mVaMjQkBLotazWbegzI+be8V3yT06C+ehD+2
GdLWAVs9hp8gPHEUShb/XrgPpDSJmFlOiyeOFBO/j4edDACKqVcwdjBOMAoGCCqF
AwcBAQIDBEAIFX0fyZe20QKKhWm6WYX+S92Gt6zaXroXOvAmayzLfZ5Sd9C2t9zZ
JSg6M8RBUYpw/8ym5ou1o2nDa09M5zF3BCCpzyCQBI+rzfISeKvPV1ROfcXiYU93
mwcl1xQV2G5/fgICB9A=
    """)
    password = u"Пароль для PFX"

    def test_shrouded_key_bag(self):
        private_key_info_expected = b64decode(b"""
MGYCAQAwHwYIKoUDBwEBAQEwEwYHKoUDAgIjAQYIKoUDBwEBAgIEQEYbRu86z+1JFKDcPDN9UbTG
G2ki9enTqos4KpUU0j9IDpl1UXiaA1YDIwUjlAp+81GkLmyt8Fw6Gt/X5JZySAY=
        """)

        pfx, tail = PFX().decode(self.pfx_raw)
        self.assertSequenceEqual(tail, b"")
        _, outer_safe_contents = pfx["authSafe"]["content"].defined
        safe_contents, tail = OctetStringSafeContents().decode(
            bytes(outer_safe_contents[0]["bagValue"]),
        )
        self.assertSequenceEqual(tail, b"")
        safe_bag = safe_contents[0]
        shrouded_key_bag, tail = PKCS8ShroudedKeyBag().decode(
            bytes(safe_bag["bagValue"]),
        )
        self.assertSequenceEqual(tail, b"")
        _, pbes2_params = shrouded_key_bag["encryptionAlgorithm"]["parameters"].defined
        _, pbkdf2_params = pbes2_params["keyDerivationFunc"]["parameters"].defined
        _, enc_scheme_params = pbes2_params["encryptionScheme"]["parameters"].defined

        key = gost34112012_pbkdf2(
            password=self.password.encode("utf-8"),
            salt=bytes(pbkdf2_params["salt"]["specified"]),
            iterations=int(pbkdf2_params["iterationCount"]),
            dklen=32,
        )
        # key = hexdec("309dd0354c5603739403f2335e9e2055138f8b5c98b63009de0635eea1fd7ba8")
        self.assertSequenceEqual(
            cfb_decrypt(
                key,
                bytes(shrouded_key_bag["encryptedData"]),
                iv=bytes(enc_scheme_params["iv"]),
                sbox="id-tc26-gost-28147-param-Z",
            ),
            private_key_info_expected,
        )

    def test_encrypted_data(self):
        cert_bag_expected = b64decode(b"""
MIIDSjCCA0YGCyqGSIb3DQEMCgEDoIIDHjCCAxoGCiqGSIb3DQEJFgGgggMKBIIDBjCCAwIwggKt
oAMCAQICEAHQaF8xH5bAAAAACycJAAEwDAYIKoUDBwEBAwIFADBgMQswCQYDVQQGEwJSVTEVMBMG
A1UEBwwM0JzQvtGB0LrQstCwMQ8wDQYDVQQKDAbQotCaMjYxKTAnBgNVBAMMIENBIGNlcnRpZmlj
YXRlIChQS0NTIzEyIGV4YW1wbGUpMB4XDTE1MDMyNzA3MjUwMFoXDTIwMDMyNzA3MjMwMFowZDEL
MAkGA1UEBhMCUlUxFTATBgNVBAcMDNCc0L7RgdC60LLQsDEPMA0GA1UECgwG0KLQmjI2MS0wKwYD
VQQDDCRUZXN0IGNlcnRpZmljYXRlIDEgKFBLQ1MjMTIgZXhhbXBsZSkwZjAfBggqhQMHAQEBATAT
BgcqhQMCAiMBBggqhQMHAQECAgNDAARA1xzymkpvr2dYJT8WTOX3Dt96/+hGsXNytUQpkWB5ImJM
4tg9AsC4RIUwV5H41MhG0uBRFweTzN6AsAdBvhTClYEJADI3MDkwMDAxo4IBKTCCASUwKwYDVR0Q
BCQwIoAPMjAxNTAzMjcwNzI1MDBagQ8yMDE2MDMyNzA3MjUwMFowDgYDVR0PAQH/BAQDAgTwMB0G
A1UdDgQWBBQhWOsRQ68yYN2Utg/owHoWcqsVbTAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUH
AwQwDAYDVR0TAQH/BAIwADCBmQYDVR0jBIGRMIGOgBQmnc7Xh5ykb5t/BMwOkxA4drfEmqFkpGIw
YDELMAkGA1UEBhMCUlUxFTATBgNVBAcMDNCc0L7RgdC60LLQsDEPMA0GA1UECgwG0KLQmjI2MSkw
JwYDVQQDDCBDQSBjZXJ0aWZpY2F0ZSAoUEtDUyMxMiBleGFtcGxlKYIQAdBoXvL8TSAAAAALJwkA
ATAMBggqhQMHAQEDAgUAA0EA9oq0Vvk8kkgIwkp0x0J5eKtia4MNTiwKAm7jgnCZIx3O98BThaTX
3ZQhEo2RL9pTCPr6wFMheeJ+YdGMReXvsjEVMBMGCSqGSIb3DQEJFTEGBAQBAAAA
        """)

        pfx, tail = PFX().decode(self.pfx_raw)
        self.assertSequenceEqual(tail, b"")
        _, outer_safe_contents = pfx["authSafe"]["content"].defined
        _, encrypted_data = outer_safe_contents[1]["bagValue"].defined
        _, pbes2_params = encrypted_data["encryptedContentInfo"]["contentEncryptionAlgorithm"]["parameters"].defined
        _, pbkdf2_params = pbes2_params["keyDerivationFunc"]["parameters"].defined
        _, enc_scheme_params = pbes2_params["encryptionScheme"]["parameters"].defined
        key = gost34112012_pbkdf2(
            password=self.password.encode("utf-8"),
            salt=bytes(pbkdf2_params["salt"]["specified"]),
            iterations=int(pbkdf2_params["iterationCount"]),
            dklen=32,
        )
        # key = hexdec("0e93d71339e7f53b79a0bc41f9109dd4fb60b30ae10736c1bb77b84c07681cfc")
        self.assertSequenceEqual(
            cfb_decrypt(
                key,
                bytes(encrypted_data["encryptedContentInfo"]["encryptedContent"]),
                iv=bytes(enc_scheme_params["iv"]),
                sbox="id-tc26-gost-28147-param-Z",
            ),
            cert_bag_expected,
        )

    def test_mac(self):
        pfx, tail = PFX().decode(self.pfx_raw)
        self.assertSequenceEqual(tail, b"")
        _, outer_safe_contents = pfx["authSafe"]["content"].defined
        mac_data = pfx["macData"]
        mac_key = gost34112012_pbkdf2(
            password=self.password.encode("utf-8"),
            salt=bytes(mac_data["macSalt"]),
            iterations=int(mac_data["iterations"]),
            dklen=96,
        )[-32:]
        # mac_key = hexdec("cadbfbf3bceaa9b79f651508fac5abbeb4a13d0bd0e1876bd3c3efb2112128a5")
        self.assertSequenceEqual(
            hmac_new(
                key=mac_key,
                msg=SafeContents(outer_safe_contents).encode(),
                digestmod=GOST34112012512,
            ).digest(),
            bytes(mac_data["mac"]["digest"]),
        )


@skipIf(not pyderasn_exists, "PyDERASN dependency is required")
class TestPFX2020(TestCase):
    """PFX test vectors from newer PKCS#12 update
    """
    ca_prv_raw = hexdec("092F8D059E97E22B90B1AE99F0087FC4D26620B91550CBB437C191005A290810")
    ca_curve = gost3410.CURVES["id-tc26-gost-3410-12-256-paramSetA"]
    ca_cert = Certificate().decod(b64decode(b"""
        MIIB+TCCAaagAwIBAgIEAYy6gTAKBggqhQMHAQEDAjA4MQ0wCwYDVQQKEwRUSzI2MS
        cwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwHhcNMDEwMTAx
        MDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA4MQ0wCwYDVQQKEwRUSzI2MScwJQYDVQQDEx
        5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwXjAXBggqhQMHAQEBATALBgkq
        hQMHAQIBAQEDQwAEQBpKgpyPDnhQAJyLqy8Qs0XQhgxEhby6tSypqYimgbjpcKqtU6
        4jpDXc3h3BxGxtl2oHJ/4YLZ/ll87dto3ltMqjgZgwgZUwYwYDVR0jBFwwWoAUrGwO
        TERmokKW4p8JOyVm88ukUyqhPKQ6MDgxDTALBgNVBAoTBFRLMjYxJzAlBgNVBAMTHk
        NBIFRLMjY6IEdPU1QgMzQuMTAtMTIgMjU2LWJpdIIEAYy6gTAdBgNVHQ4EFgQUrGwO
        TERmokKW4p8JOyVm88ukUyowDwYDVR0TAQH/BAUwAwEB/zAKBggqhQMHAQEDAgNBAB
        Gg3nhgQ5oCKbqlEdVaRxH+1WX4wVkawGXuTYkr1AC2OWw3ZC14Vvg3nazm8UMWUZtk
        vu1kJcHQ4jFKkjUeg2E=
    """))
    ca_pub = gost3410.pub_unmarshal(bytes(OctetString().decod(bytes(
        ca_cert["tbsCertificate"]["subjectPublicKeyInfo"]["subjectPublicKey"]
    ))))
    password = u"Пароль для PFX".encode("utf-8")
    cert_test = Certificate().decod(b64decode(b"""
        MIICLjCCAdugAwIBAgIEAYy6hDAKBggqhQMHAQEDAjA4MQ0wCwYDVQQKEwRUSzI2MS
        cwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwHhcNMDEwMTAx
        MDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA7MQ0wCwYDVQQKEwRUSzI2MSowKAYDVQQDEy
        FPUklHSU5BVE9SOiBHT1NUIDM0LjEwLTEyIDUxMi1iaXQwgaAwFwYIKoUDBwEBAQIw
        CwYJKoUDBwECAQIBA4GEAASBgLSLt1q8KQ4YZVxioU+1LV9QhE7MHR9gBEh7S1yVNG
        lqt7+rNG5VFqmrPM74rbUsOlhV8M+zZKprXdk35Oz8lSW/n2oIUHZxikXIH/SSHj4r
        v3K/Puvz7hYTQSZl/xPdp78nUmjrEa6d5wfX8biEy2z0dgufFvAkMw1Ua4gdXqDOo4
        GHMIGEMGMGA1UdIwRcMFqAFKxsDkxEZqJCluKfCTslZvPLpFMqoTykOjA4MQ0wCwYD
        VQQKEwRUSzI2MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaX
        SCBAGMuoEwHQYDVR0OBBYEFH4GVwmYDK1rCKhX7nkAWDrJ16CkMAoGCCqFAwcBAQMC
        A0EACl6p8dAbpi9Hk+3mgMyI0WIh17IrlrSp/mB0F7ZzMt8XUD1Dwz3JrrnxeXnfMv
        OA5BdUJ9hCyDgMVAGs/IcEEA==
    """))
    prv_test_raw = b64decode("""
        MIHiAgEBMBcGCCqFAwcBAQECMAsGCSqFAwcBAgECAQRAEWkl+eblsHWs86SNgRKq
        SxMOgGhbvR/uZ5/WWfdNG1axvUwVhpcXIxDZUmzQuNzqJBkseI7f5/JjXyTFRF1a
        +YGBgQG0i7davCkOGGVcYqFPtS1fUIROzB0fYARIe0tclTRpare/qzRuVRapqzzO
        +K21LDpYVfDPs2Sqa13ZN+Ts/JUlv59qCFB2cYpFyB/0kh4+K79yvz7r8+4WE0Em
        Zf8T3ae/J1Jo6xGunecH1/G4hMts9HYLnxbwJDMNVGuIHV6gzg==
    """)

    def test_cert_and_encrypted_key(self):
        pfx_raw = b64decode(b"""
            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
        """)
        pfx = PFX().decod(pfx_raw)
        _, outer_safe_contents = pfx["authSafe"]["content"].defined

        safe_contents = OctetStringSafeContents().decod(bytes(
            outer_safe_contents[0]["bagValue"]
        ))
        safe_bag = safe_contents[0]
        self.assertEqual(safe_bag["bagId"], id_pkcs12_bagtypes_certBag)
        cert_bag = CertBag().decod(bytes(safe_bag["bagValue"]))
        self.assertEqual(cert_bag["certId"], id_pkcs9_certTypes_x509Certificate)
        _, cert = cert_bag["certValue"].defined
        self.assertEqual(Certificate(cert), self.cert_test)

        safe_contents = OctetStringSafeContents().decod(bytes(
            outer_safe_contents[1]["bagValue"]
        ))
        safe_bag = safe_contents[0]
        self.assertEqual(safe_bag["bagId"], id_pkcs12_bagtypes_pkcs8ShroudedKeyBag)
        shrouded_key_bag = PKCS8ShroudedKeyBag().decod(bytes(safe_bag["bagValue"]))
        _, pbes2_params = shrouded_key_bag["encryptionAlgorithm"]["parameters"].defined
        _, pbkdf2_params = pbes2_params["keyDerivationFunc"]["parameters"].defined
        _, enc_scheme_params = pbes2_params["encryptionScheme"]["parameters"].defined
        ukm = bytes(enc_scheme_params["ukm"])
        key = gost34112012_pbkdf2(
            password=self.password,
            salt=bytes(pbkdf2_params["salt"]["specified"]),
            iterations=int(pbkdf2_params["iterationCount"]),
            dklen=32,
        )
        # key = hexdec("4b7ae649ca31dd5fe3243a91a5188c03f1d7049bec8e0d241c0e1e8c39ea4c1f")
        key_enc, key_mac = kdf_tree_gostr3411_2012_256(
            key, b"kdf tree", ukm[GOST3412Kuznechik.blocksize // 2:], 2,
        )
        ciphertext = bytes(shrouded_key_bag["encryptedData"])
        plaintext = ctr_acpkm(
            GOST3412Kuznechik,
            GOST3412Kuznechik(key_enc).encrypt,
            section_size=256 * 1024,
            bs=GOST3412Kuznechik.blocksize,
            data=ciphertext,
            iv=ukm[:GOST3412Kuznechik.blocksize // 2],
        )
        mac_expected = plaintext[-GOST3412Kuznechik.blocksize:]
        plaintext = plaintext[:-GOST3412Kuznechik.blocksize]
        mac = omac(
            GOST3412Kuznechik(key_mac).encrypt,
            GOST3412Kuznechik.blocksize,
            plaintext,
        )
        self.assertSequenceEqual(mac, mac_expected)
        self.assertSequenceEqual(plaintext, self.prv_test_raw)

        mac_data = pfx["macData"]
        mac_key = gost34112012_pbkdf2(
            password=self.password,
            salt=bytes(mac_data["macSalt"]),
            iterations=int(mac_data["iterations"]),
            dklen=96,
        )[-32:]
        # mac_key = hexdec("a81d1bc91a4a5cf1fd7320f92dda7e5b285816c3b20826a382d7ed0cbf3a9bf4")
        self.assertSequenceEqual(
            hmac_new(
                key=mac_key,
                msg=SafeContents(outer_safe_contents).encode(),
                digestmod=GOST34112012512,
            ).digest(),
            bytes(mac_data["mac"]["digest"]),
        )
        self.assertTrue(gost3410.verify(
            self.ca_curve,
            self.ca_pub,
            GOST34112012256(cert["tbsCertificate"].encode()).digest()[::-1],
            bytes(cert["signatureValue"]),
        ))

    def test_encrypted_cert_and_key(self):
        pfx_raw = b64decode(b"""
            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
        """)
        pfx = PFX().decod(pfx_raw)
        _, outer_safe_contents = pfx["authSafe"]["content"].defined

        encrypted_data = EncryptedData().decod(bytes(
            outer_safe_contents[0]["bagValue"]
        ))
        eci = encrypted_data["encryptedContentInfo"]
        self.assertEqual(eci["contentEncryptionAlgorithm"]["algorithm"], id_pbes2)
        pbes2_params = PBES2Params().decod(bytes(
            eci["contentEncryptionAlgorithm"]["parameters"]
        ))
        _, pbkdf2_params = pbes2_params["keyDerivationFunc"]["parameters"].defined
        _, enc_scheme_params = pbes2_params["encryptionScheme"]["parameters"].defined
        ukm = bytes(enc_scheme_params["ukm"])
        key = gost34112012_pbkdf2(
            password=self.password,
            salt=bytes(pbkdf2_params["salt"]["specified"]),
            iterations=int(pbkdf2_params["iterationCount"]),
            dklen=32,
        )
        # key = hexdec("d066a96fb326ba896a2352d3f40240a4ded6e7e7bd5b4db6b5241d631c8c381c")
        key_enc, key_mac = kdf_tree_gostr3411_2012_256(
            key, b"kdf tree", ukm[GOST3412Magma.blocksize // 2:], 2,
        )
        ciphertext = bytes(eci["encryptedContent"])
        plaintext = ctr_acpkm(
            GOST3412Magma,
            GOST3412Magma(key_enc).encrypt,
            section_size=8 * 1024,
            bs=GOST3412Magma.blocksize,
            data=ciphertext,
            iv=ukm[:GOST3412Magma.blocksize // 2],
        )
        mac_expected = plaintext[-GOST3412Magma.blocksize:]
        plaintext = plaintext[:-GOST3412Magma.blocksize]
        mac = omac(
            GOST3412Magma(key_mac).encrypt,
            GOST3412Magma.blocksize,
            plaintext,
        )
        self.assertSequenceEqual(mac, mac_expected)

        safe_contents = SafeContents().decod(plaintext)
        safe_bag = safe_contents[0]
        self.assertEqual(safe_bag["bagId"], id_pkcs12_bagtypes_certBag)
        cert_bag = CertBag().decod(bytes(safe_bag["bagValue"]))
        self.assertEqual(cert_bag["certId"], id_pkcs9_certTypes_x509Certificate)
        _, cert = cert_bag["certValue"].defined
        self.assertEqual(Certificate(cert), self.cert_test)

        safe_contents = OctetStringSafeContents().decod(bytes(
            outer_safe_contents[1]["bagValue"]
        ))
        safe_bag = safe_contents[0]
        self.assertEqual(safe_bag["bagId"], id_pkcs12_bagtypes_pkcs8ShroudedKeyBag)
        shrouded_key_bag = PKCS8ShroudedKeyBag().decod(bytes(safe_bag["bagValue"]))
        _, pbes2_params = shrouded_key_bag["encryptionAlgorithm"]["parameters"].defined
        _, pbkdf2_params = pbes2_params["keyDerivationFunc"]["parameters"].defined
        _, enc_scheme_params = pbes2_params["encryptionScheme"]["parameters"].defined
        ukm = bytes(enc_scheme_params["ukm"])
        key = gost34112012_pbkdf2(
            password=self.password,
            salt=bytes(pbkdf2_params["salt"]["specified"]),
            iterations=int(pbkdf2_params["iterationCount"]),
            dklen=32,
        )
        # key = hexdec("f840d001fd11441e0fb7ccf48f471915e5bf35275309dbe7ade9da4fe460ba7e")
        ciphertext = bytes(shrouded_key_bag["encryptedData"])
        plaintext = ctr_acpkm(
            GOST3412Magma,
            GOST3412Magma(key).encrypt,
            section_size=8 * 1024,
            bs=GOST3412Magma.blocksize,
            data=ciphertext,
            iv=ukm[:GOST3412Magma.blocksize // 2],
        )
        self.assertSequenceEqual(plaintext, self.prv_test_raw)

        mac_data = pfx["macData"]
        mac_key = gost34112012_pbkdf2(
            password=self.password,
            salt=bytes(mac_data["macSalt"]),
            iterations=int(mac_data["iterations"]),
            dklen=96,
        )[-32:]
        # mac_key = hexdec("084f81782af1534ffd67e3c579c14cb45d7a6f659f46fdbb51a552e874e66fb2")
        self.assertSequenceEqual(
            hmac_new(
                key=mac_key,
                msg=SafeContents(outer_safe_contents).encode(),
                digestmod=GOST34112012512,
            ).digest(),
            bytes(mac_data["mac"]["digest"]),
        )

    def test_dh(self):
        curve = gost3410.CURVES["id-tc26-gost-3410-12-256-paramSetA"]
        # sender_prv_raw = hexdec("0B20810E449978C7C3B76C6FF77A16C532421139344A058EF56310B6B6F377E8")
        sender_cert = Certificate().decod(b64decode("""
            MIIB6zCCAZigAwIBAgIEAYy6gjAKBggqhQMHAQEDAjA4MQ0wCwYDVQQKEwRUSzI2
            MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwHhcNMDEw
            MTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA7MQ0wCwYDVQQKEwRUSzI2MSowKAYD
            VQQDEyFPUklHSU5BVE9SOiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwXjAXBggqhQMH
            AQEBATALBgkqhQMHAQIBAQEDQwAEQJYpDRNiWWqDgaZje0EmLLOldQ35o5X1ZuZN
            SKequYQc/soI3OgDMWD7ThJJCk01IelCeb6MsBmG4lol+pnpVtOjgYcwgYQwYwYD
            VR0jBFwwWoAUrGwOTERmokKW4p8JOyVm88ukUyqhPKQ6MDgxDTALBgNVBAoTBFRL
            MjYxJzAlBgNVBAMTHkNBIFRLMjY6IEdPU1QgMzQuMTAtMTIgMjU2LWJpdIIEAYy6
            gTAdBgNVHQ4EFgQUPx5RgcjkifhlJm4/jQdkbm30rVQwCgYIKoUDBwEBAwIDQQA6
            8x7Vk6PvP/8xOGHhf8PuqaXAYskSyJPuBu+3Bo/PEj10devwc1J9uYWIDCGdKKPy
            bSlnQHqUPBBPM30YX1YN
        """))
        recipient_prv_raw = hexdec("0DC8DC1FF2BC114BABC3F1CA8C51E4F58610427E197B1C2FBDBA4AE58CBFB7CE")[::-1]
        recipient_prv = gost3410.prv_unmarshal(recipient_prv_raw)
        recipient_cert = Certificate().decod(b64decode("""
            MIIB6jCCAZegAwIBAgIEAYy6gzAKBggqhQMHAQEDAjA4MQ0wCwYDVQQKEwRUSzI2
            MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwHhcNMDEw
            MTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA6MQ0wCwYDVQQKEwRUSzI2MSkwJwYD
            VQQDEyBSRUNJUElFTlQ6IEdPU1QgMzQuMTAtMTIgMjU2LWJpdDBeMBcGCCqFAwcB
            AQEBMAsGCSqFAwcBAgEBAQNDAARAvyeCGXMsYwpYe5aE0w8w3m4vpKQapGInqpnF
            lv7h08psFP0s1W80q3BR534F4TmR+o5+iU+AW6ycvWuc73JEQ6OBhzCBhDBjBgNV
            HSMEXDBagBSsbA5MRGaiQpbinwk7JWbzy6RTKqE8pDowODENMAsGA1UEChMEVEsy
            NjEnMCUGA1UEAxMeQ0EgVEsyNjogR09TVCAzNC4xMC0xMiAyNTYtYml0ggQBjLqB
            MB0GA1UdDgQWBBQ35gHPN1bx8l2eEMTbrtIg+5MU0TAKBggqhQMHAQEDAgNBABF2
            RHDaRqQuBS2yu7yGIGFgA6c/LG4GKjSOwYsRVmXJNNkQ4TB7PB8j3q7gx2koPsVB
            m90WfMWSL6SNSh3muuM=
        """))
        self.assertTrue(gost3410.verify(
            self.ca_curve,
            self.ca_pub,
            GOST34112012256(sender_cert["tbsCertificate"].encode()).digest()[::-1],
            bytes(sender_cert["signatureValue"]),
        ))
        self.assertTrue(gost3410.verify(
            self.ca_curve,
            self.ca_pub,
            GOST34112012256(recipient_cert["tbsCertificate"].encode()).digest()[::-1],
            bytes(recipient_cert["signatureValue"]),
        ))

        pfx_raw = b64decode("""
            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
            kxFG6QUFH8uuoX8=
        """)
        pfx = PFX().decod(pfx_raw)
        self.assertEqual(pfx["authSafe"]["contentType"], id_signedData)

        sd = SignedData().decod(bytes(pfx["authSafe"]["content"]))
        self.assertEqual(sd["certificates"][0]["certificate"], sender_cert)
        si = sd["signerInfos"][0]
        self.assertEqual(
            si["digestAlgorithm"]["algorithm"],
            id_tc26_gost3411_2012_256,
        )
        digest = [
            bytes(attr["attrValues"][0].defined[1]) for attr in si["signedAttrs"]
            if attr["attrType"] == id_messageDigest
        ][0]
        sender_pub = gost3410.pub_unmarshal(bytes(OctetString().decod(bytes(
            sender_cert["tbsCertificate"]["subjectPublicKeyInfo"]["subjectPublicKey"]
        ))))
        content = bytes(sd["encapContentInfo"]["eContent"])
        self.assertSequenceEqual(digest, GOST34112012256(content).digest())
        self.assertTrue(gost3410.verify(
            curve,
            sender_pub,
            GOST34112012256(
                SignedAttributes(si["signedAttrs"]).encode()
            ).digest()[::-1],
            bytes(si["signature"]),
        ))

        outer_safe_contents = SafeContents().decod(content)

        safe_bag = outer_safe_contents[0]
        self.assertEqual(safe_bag["bagId"], id_data)
        safe_contents = OctetStringSafeContents().decod(bytes(safe_bag["bagValue"]))
        safe_bag = safe_contents[0]
        self.assertEqual(safe_bag["bagId"], id_pkcs12_bagtypes_certBag)
        cert_bag = CertBag().decod(bytes(safe_bag["bagValue"]))
        self.assertEqual(cert_bag["certId"], id_pkcs9_certTypes_x509Certificate)
        _, cert = cert_bag["certValue"].defined
        self.assertEqual(Certificate(cert), self.cert_test)

        safe_bag = outer_safe_contents[1]
        self.assertEqual(safe_bag["bagId"], id_envelopedData)
        ed = EnvelopedData().decod(bytes(safe_bag["bagValue"]))
        kari = ed["recipientInfos"][0]["kari"]
        ukm = bytes(kari["ukm"])
        self.assertEqual(
            kari["keyEncryptionAlgorithm"]["algorithm"],
            id_gostr3412_2015_kuznyechik_wrap_kexp15,
        )
        self.assertEqual(
            kari["keyEncryptionAlgorithm"]["parameters"].defined[1]["algorithm"],
            id_tc26_agreement_gost3410_2012_256,
        )
        kexp = bytes(kari["recipientEncryptedKeys"][0]["encryptedKey"])
        keymat = keg(curve, recipient_prv, sender_pub, ukm)
        kim, kek = keymat[:KEYSIZE], keymat[KEYSIZE:]
        cek = kimp15(
            GOST3412Kuznechik(kek).encrypt,
            GOST3412Kuznechik(kim).encrypt,
            GOST3412Kuznechik.blocksize,
            kexp,
            ukm[24:24 + GOST3412Kuznechik.blocksize // 2],
        )
        eci = ed["encryptedContentInfo"]
        self.assertEqual(
            eci["contentEncryptionAlgorithm"]["algorithm"],
            id_gostr3412_2015_kuznyechik_ctracpkm,
        )
        eci_ukm = bytes(
            eci["contentEncryptionAlgorithm"]["parameters"].defined[1]["ukm"]
        )
        content = ctr_acpkm(
            GOST3412Kuznechik,
            GOST3412Kuznechik(cek).encrypt,
            256 * 1024,
            GOST3412Kuznechik.blocksize,
            bytes(eci["encryptedContent"]),
            eci_ukm[:GOST3412Kuznechik.blocksize // 2],
        )

        safe_contents = SafeContents().decod(content)
        safe_bag = safe_contents[0]
        self.assertEqual(safe_bag["bagId"], id_pkcs12_bagtypes_keyBag)
        KeyBag().decod(bytes(safe_bag["bagValue"]))
        self.assertSequenceEqual(bytes(safe_bag["bagValue"]), self.prv_test_raw)
