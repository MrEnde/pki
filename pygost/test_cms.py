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
from unittest import skipIf
from unittest import TestCase

from six import text_type

from pygost.gost28147 import cfb_decrypt
from pygost.gost3410 import CURVES
from pygost.gost3410 import prv_unmarshal
from pygost.gost3410 import pub_marshal
from pygost.gost3410 import pub_unmarshal
from pygost.gost3410 import public_key
from pygost.gost3410 import verify
from pygost.gost3410_vko import kek_34102012256
from pygost.gost3410_vko import ukm_unmarshal
from pygost.gost34112012256 import GOST34112012256
from pygost.gost34112012512 import GOST34112012512
from pygost.gost3412 import GOST3412Kuznechik
from pygost.gost3412 import GOST3412Magma
from pygost.gost3413 import ctr_acpkm
from pygost.gost3413 import KEYSIZE
from pygost.gost3413 import mac as omac
from pygost.kdf import kdf_tree_gostr3411_2012_256
from pygost.kdf import keg
from pygost.utils import hexdec
from pygost.wrap import kimp15
from pygost.wrap import unwrap_cryptopro
from pygost.wrap import unwrap_gost

try:
    from pyderasn import DecodePathDefBy
    from pyderasn import OctetString

    from pygost.asn1schemas.cms import ContentInfo
    from pygost.asn1schemas.cms import SignedAttributes
    from pygost.asn1schemas.oids import id_cms_mac_attr
    from pygost.asn1schemas.oids import id_envelopedData
    from pygost.asn1schemas.oids import id_gostr3412_2015_kuznyechik_ctracpkm
    from pygost.asn1schemas.oids import id_gostr3412_2015_kuznyechik_ctracpkm_omac
    from pygost.asn1schemas.oids import id_gostr3412_2015_kuznyechik_wrap_kexp15
    from pygost.asn1schemas.oids import id_gostr3412_2015_magma_ctracpkm
    from pygost.asn1schemas.oids import id_gostr3412_2015_magma_ctracpkm_omac
    from pygost.asn1schemas.oids import id_gostr3412_2015_magma_wrap_kexp15
    from pygost.asn1schemas.oids import id_messageDigest
    from pygost.asn1schemas.oids import id_tc26_agreement_gost3410_2012_256
    from pygost.asn1schemas.oids import id_tc26_agreement_gost3410_2012_512
    from pygost.asn1schemas.oids import id_tc26_gost3410_2012_256
    from pygost.asn1schemas.oids import id_tc26_gost3410_2012_512
    from pygost.asn1schemas.oids import id_tc26_gost3410_2012_512_paramSetA
    from pygost.asn1schemas.oids import id_tc26_gost3411_2012_256
    from pygost.asn1schemas.oids import id_tc26_gost3411_2012_512
    from pygost.asn1schemas.x509 import Certificate
    from pygost.asn1schemas.x509 import GostR34102012PublicKeyParameters
except ImportError:
    pyderasn_exists = False
else:
    pyderasn_exists = True


@skipIf(not pyderasn_exists, "PyDERASN dependency is required")
class TestSigned(TestCase):
    """SignedData test vectors from "Использование
    алгоритмов ГОСТ 28147-89, ГОСТ Р 34.11 и ГОСТ Р 34.10 в
    криптографических сообщениях формата CMS" (TK26CMS.pdf)
    """

    def process_cms(
            self,
            content_info_raw,
            prv_key_raw,
            curve_name,
            hasher,
    ):
        content_info, tail = ContentInfo().decode(content_info_raw)
        self.assertSequenceEqual(tail, b"")
        self.assertIsNotNone(content_info["content"].defined)
        _, signed_data = content_info["content"].defined
        self.assertEqual(len(signed_data["signerInfos"]), 1)
        curve = CURVES[curve_name]
        self.assertTrue(verify(
            curve,
            public_key(curve, prv_unmarshal(prv_key_raw)),
            hasher(bytes(signed_data["encapContentInfo"]["eContent"])).digest()[::-1],
            bytes(signed_data["signerInfos"][0]["signature"]),
        ))

    def test_256(self):
        content_info_raw = b64decode("""
MIIBBQYJKoZIhvcNAQcCoIH3MIH0AgEBMQ4wDAYIKoUDBwEBAgIFADAbBgkqhkiG
9w0BBwGgDgQMVGVzdCBtZXNzYWdlMYHBMIG+AgEBMFswVjEpMCcGCSqGSIb3DQEJ
ARYaR29zdFIzNDEwLTIwMTJAZXhhbXBsZS5jb20xKTAnBgNVBAMTIEdvc3RSMzQx
MC0yMDEyICgyNTYgYml0KSBleGFtcGxlAgEBMAwGCCqFAwcBAQICBQAwDAYIKoUD
BwEBAQEFAARAkptb2ekZbC94FaGDQeP70ExvTkXtOY9zgz3cCco/hxPhXUVo3eCx
VNwDQ8enFItJZ8DEX4blZ8QtziNCMl5HbA==
        """)
        prv_key_raw = hexdec("BFCF1D623E5CDD3032A7C6EABB4A923C46E43D640FFEAAF2C3ED39A8FA399924")[::-1]
        self.process_cms(
            content_info_raw,
            prv_key_raw,
            "id-GostR3410-2001-CryptoPro-XchA-ParamSet",
            GOST34112012256,
        )

    def test_512(self):
        content_info_raw = b64decode("""
MIIBSQYJKoZIhvcNAQcCoIIBOjCCATYCAQExDjAMBggqhQMHAQECAwUAMBsGCSqG
SIb3DQEHAaAOBAxUZXN0IG1lc3NhZ2UxggECMIH/AgEBMFswVjEpMCcGCSqGSIb3
DQEJARYaR29zdFIzNDEwLTIwMTJAZXhhbXBsZS5jb20xKTAnBgNVBAMTIEdvc3RS
MzQxMC0yMDEyICg1MTIgYml0KSBleGFtcGxlAgEBMAwGCCqFAwcBAQIDBQAwDAYI
KoUDBwEBAQIFAASBgFyVohNhMHUi/+RAF3Gh/cC7why6v+4jPWVlx1TYlXtV8Hje
hI2Y+rP52/LO6EUHG/XcwCBbUxmRWsbUSRRBAexmaafkSdvv2FFwC8kHOcti+UPX
PS+KRYxT8vhcsBLWWxDkc1McI7aF09hqtED36mQOfACzeJjEoUjALpmJob1V
        """)
        prv_key_raw = hexdec("3FC01CDCD4EC5F972EB482774C41E66DB7F380528DFE9E67992BA05AEE462435757530E641077CE587B976C8EEB48C48FD33FD175F0C7DE6A44E014E6BCB074B")[::-1]
        self.process_cms(
            content_info_raw,
            prv_key_raw,
            "id-tc26-gost-3410-12-512-paramSetB",
            GOST34112012512,
        )


@skipIf(not pyderasn_exists, "PyDERASN dependency is required")
class TestDigested(TestCase):
    """DigestedData test vectors from "Использование
    алгоритмов ГОСТ 28147-89, ГОСТ Р 34.11 и ГОСТ Р 34.10 в
    криптографических сообщениях формата CMS" (TK26CMS.pdf)
    """

    def process_cms(self, content_info_raw, hasher):
        content_info, tail = ContentInfo().decode(content_info_raw)
        self.assertSequenceEqual(tail, b"")
        self.assertIsNotNone(content_info["content"].defined)
        _, digested_data = content_info["content"].defined
        self.assertSequenceEqual(
            hasher(bytes(digested_data["encapContentInfo"]["eContent"])).digest(),
            bytes(digested_data["digest"]),
        )

    def test_256(self):
        content_info_raw = b64decode("""
MIGdBgkqhkiG9w0BBwWggY8wgYwCAQAwDAYIKoUDBwEBAgIFADBXBgkqhkiG9w0B
BwGgSgRI0eUg4uXy8OgsINHy8Ojh7uboIOLt8/boLCDi5f7y+iDxIOzu8P8g8fLw
5evg7Ogg7eAg9fDg4fD7/yDv6/rq+yDI4+7w5eL7BCCd0v5OkECeXah/U5dtdAWw
wMrGKPxmmnQdUAY8VX6PUA==
        """)
        self.process_cms(content_info_raw, GOST34112012256)

    def test_512(self):
        content_info_raw = b64decode("""
MIG0BgkqhkiG9w0BBwWggaYwgaMCAQAwDAYIKoUDBwEBAgMFADBOBgkqhkiG9w0B
BwGgQQQ/MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx
MjM0NTY3ODkwMTIzNDU2Nzg5MDEyBEAbVNAaSvW51cw9htaNKFRisZq8JHUiLzXA
hRIr5Lof+gCtMPh2ezqCOExldPAkwxHipIEzKwjvf0F5eJHBZG9I
        """)
        self.process_cms(content_info_raw, GOST34112012512)


@skipIf(not pyderasn_exists, "PyDERASN dependency is required")
class TestEnvelopedKTRI(TestCase):
    """EnvelopedData KeyTransRecipientInfo-based test vectors from
    "Использование алгоритмов ГОСТ 28147-89, ГОСТ Р 34.11 и ГОСТ Р 34.10
    в криптографических сообщениях формата CMS" (TK26CMS.pdf)
    """

    def process_cms(
            self,
            content_info_raw,
            prv_key_our,
            curve_name,
            keker,
            plaintext_expected,
    ):
        sbox = "id-tc26-gost-28147-param-Z"
        content_info, tail = ContentInfo().decode(content_info_raw, ctx={
            "defines_by_path": [
                (
                    (
                        "content",
                        DecodePathDefBy(id_envelopedData),
                        "recipientInfos",
                        any,
                        "ktri",
                        "encryptedKey",
                        DecodePathDefBy(spki_algorithm),
                        "transportParameters",
                        "ephemeralPublicKey",
                        "algorithm",
                        "algorithm",
                    ),
                    (
                        (
                            ("..", "subjectPublicKey"),
                            {
                                id_tc26_gost3410_2012_256: OctetString(),
                                id_tc26_gost3410_2012_512: OctetString(),
                            },
                        ),
                    ),
                ) for spki_algorithm in (
                    id_tc26_gost3410_2012_256,
                    id_tc26_gost3410_2012_512,
                )
            ],
        })
        self.assertSequenceEqual(tail, b"")
        self.assertIsNotNone(content_info["content"].defined)
        _, enveloped_data = content_info["content"].defined
        eci = enveloped_data["encryptedContentInfo"]
        ri = enveloped_data["recipientInfos"][0]
        self.assertIsNotNone(ri["ktri"]["encryptedKey"].defined)
        _, encrypted_key = ri["ktri"]["encryptedKey"].defined
        ukm = bytes(encrypted_key["transportParameters"]["ukm"])
        spk = encrypted_key["transportParameters"]["ephemeralPublicKey"]["subjectPublicKey"]
        self.assertIsNotNone(spk.defined)
        _, pub_key_their = spk.defined
        curve = CURVES[curve_name]
        kek = keker(curve, prv_key_our, bytes(pub_key_their), ukm)
        key_wrapped = bytes(encrypted_key["sessionEncryptedKey"]["encryptedKey"])
        mac = bytes(encrypted_key["sessionEncryptedKey"]["macKey"])
        cek = unwrap_cryptopro(kek, ukm + key_wrapped + mac, sbox=sbox)
        ciphertext = bytes(eci["encryptedContent"])
        self.assertIsNotNone(eci["contentEncryptionAlgorithm"]["parameters"].defined)
        _, encryption_params = eci["contentEncryptionAlgorithm"]["parameters"].defined
        iv = bytes(encryption_params["iv"])
        self.assertSequenceEqual(
            cfb_decrypt(cek, ciphertext, iv, sbox=sbox, mesh=True),
            plaintext_expected,
        )

    def test_256(self):
        content_info_raw = b64decode("""
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
        """)
        prv_key_our = hexdec("BFCF1D623E5CDD3032A7C6EABB4A923C46E43D640FFEAAF2C3ED39A8FA399924")[::-1]

        def keker(curve, prv, pub, ukm):
            return kek_34102012256(
                curve,
                prv_unmarshal(prv),
                pub_unmarshal(pub),
                ukm_unmarshal(ukm),
            )

        self.process_cms(
            content_info_raw,
            prv_key_our,
            "id-GostR3410-2001-CryptoPro-XchA-ParamSet",
            keker,
            b"Test data to encrypt.\n" * 100,
        )

    def test_512(self):
        content_info_raw = b64decode("""
MIIB0gYJKoZIhvcNAQcDoIIBwzCCAb8CAQAxggF8MIIBeAIBADBbMFYxKTAnBgkq
hkiG9w0BCQEWGkdvc3RSMzQxMC0yMDEyQGV4YW1wbGUuY29tMSkwJwYDVQQDEyBH
b3N0UjM0MTAtMjAxMiA1MTIgYml0cyBleGNoYW5nZQIBATAhBggqhQMHAQEBAjAV
BgkqhQMHAQIBAgIGCCqFAwcBAQIDBIHyMIHvMCgEIIsYzbVLn33aLinQ7SLNA7y+
Lrm02khqDCfXrNS9iiMhBATerS8zoIHCBgkqhQMHAQIFAQGggaowIQYIKoUDBwEB
AQIwFQYJKoUDBwECAQICBggqhQMHAQECAwOBhAAEgYAYiTVLKpSGaAvjJEDQ0hdK
qR/jek5Q9Q2pXC+NkOimQh7dpCi+wcaHlPcBk96hmpnOFvLaiokX8V6jqtBl5gdk
M40kOXv8kcDdTzEVKA/ZLxA8xanL+gTD6ZjaPsUu06nsA2MoMBWcHLUzueaP3bGT
/yHTV+Za5xdcQehag/lNBgQIvCw4uUl0XC4wOgYJKoZIhvcNAQcBMB8GBiqFAwIC
FTAVBAj+1QzaXaN9FwYJKoUDBwECBQEBgAyK54euw0sHhEVEkA0=
        """)
        prv_key_our = hexdec("3FC01CDCD4EC5F972EB482774C41E66DB7F380528DFE9E67992BA05AEE462435757530E641077CE587B976C8EEB48C48FD33FD175F0C7DE6A44E014E6BCB074B")[::-1]

        def keker(curve, prv, pub, ukm):
            return kek_34102012256(
                curve,
                prv_unmarshal(prv),
                pub_unmarshal(pub),
                ukm_unmarshal(ukm),
            )

        self.process_cms(
            content_info_raw,
            prv_key_our,
            "id-tc26-gost-3410-12-512-paramSetB",
            keker,
            b"Test message",
        )


@skipIf(not pyderasn_exists, "PyDERASN dependency is required")
class TestEnvelopedKARI(TestCase):
    """EnvelopedData KeyAgreeRecipientInfo-based test vectors from
    "Использование алгоритмов ГОСТ 28147-89, ГОСТ Р 34.11 и ГОСТ Р 34.10
    в криптографических сообщениях формата CMS" (TK26CMS.pdf)
    """

    def process_cms(
            self,
            content_info_raw,
            prv_key_our,
            curve_name,
            keker,
            plaintext_expected,
    ):
        sbox = "id-tc26-gost-28147-param-Z"
        content_info, tail = ContentInfo().decode(content_info_raw, ctx={
            "defines_by_path": [
                (
                    (
                        "content",
                        DecodePathDefBy(id_envelopedData),
                        "recipientInfos",
                        any,
                        "kari",
                        "originator",
                        "originatorKey",
                        "algorithm",
                        "algorithm",
                    ),
                    (
                        (
                            ("..", "publicKey"),
                            {
                                id_tc26_gost3410_2012_256: OctetString(),
                                id_tc26_gost3410_2012_512: OctetString(),
                            },
                        ),
                    ),
                ) for _ in (
                    id_tc26_gost3410_2012_256,
                    id_tc26_gost3410_2012_512,
                )
            ],
        })
        self.assertSequenceEqual(tail, b"")
        self.assertIsNotNone(content_info["content"].defined)
        _, enveloped_data = content_info["content"].defined
        eci = enveloped_data["encryptedContentInfo"]
        kari = enveloped_data["recipientInfos"][0]["kari"]
        self.assertIsNotNone(kari["originator"]["originatorKey"]["publicKey"].defined)
        _, pub_key_their = kari["originator"]["originatorKey"]["publicKey"].defined
        ukm = bytes(kari["ukm"])
        rek = kari["recipientEncryptedKeys"][0]
        curve = CURVES[curve_name]
        kek = keker(curve, prv_key_our, bytes(pub_key_their), ukm)
        self.assertIsNotNone(rek["encryptedKey"].defined)
        _, encrypted_key = rek["encryptedKey"].defined
        key_wrapped = bytes(encrypted_key["encryptedKey"])
        mac = bytes(encrypted_key["macKey"])
        cek = unwrap_gost(kek, ukm + key_wrapped + mac, sbox=sbox)
        ciphertext = bytes(eci["encryptedContent"])
        self.assertIsNotNone(eci["contentEncryptionAlgorithm"]["parameters"].defined)
        _, encryption_params = eci["contentEncryptionAlgorithm"]["parameters"].defined
        iv = bytes(encryption_params["iv"])
        self.assertSequenceEqual(
            cfb_decrypt(cek, ciphertext, iv, sbox=sbox, mesh=True),
            plaintext_expected,
        )

    def test_256(self):
        content_info_raw = b64decode("""
MIIBhgYJKoZIhvcNAQcDoIIBdzCCAXMCAQIxggEwoYIBLAIBA6BooWYwHwYIKoUD
BwEBAQEwEwYHKoUDAgIkAAYIKoUDBwEBAgIDQwAEQPAdWM4pO38iZ49UjaXQpq+a
jhTa4KwY4B9TFMK7AiYmbFKE0eX/wvu69kFMQ2o3OJTnMOlr1WHiPYOmNO6C5hOh
CgQIX+vNomZakEIwIgYIKoUDBwEBAQEwFgYHKoUDAgINADALBgkqhQMHAQIFAQEw
gYwwgYkwWzBWMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAtMjAxMkBleGFtcGxl
LmNvbTEpMCcGA1UEAxMgR29zdFIzNDEwLTIwMTIgMjU2IGJpdHMgZXhjaGFuZ2UC
AQEEKjAoBCCNhrZOr7x2fsjjQAeDMv/tSoNRQSSQzzxgqdnYxJ3fIAQEgYLqVDA6
BgkqhkiG9w0BBwEwHwYGKoUDAgIVMBUECHVmR/S+hlYiBgkqhQMHAQIFAQGADEI9
UNjyuY+54uVcHw==
        """)
        prv_key_our = hexdec("BFCF1D623E5CDD3032A7C6EABB4A923C46E43D640FFEAAF2C3ED39A8FA399924")[::-1]

        def keker(curve, prv, pub, ukm):
            return kek_34102012256(
                curve,
                prv_unmarshal(prv),
                pub_unmarshal(pub),
                ukm_unmarshal(ukm),
            )

        self.process_cms(
            content_info_raw,
            prv_key_our,
            "id-GostR3410-2001-CryptoPro-XchA-ParamSet",
            keker,
            b"Test message",
        )

    def test_512(self):
        content_info_raw = b64decode("""
MIIBzAYJKoZIhvcNAQcDoIIBvTCCAbkCAQIxggF2oYIBcgIBA6CBraGBqjAhBggq
hQMHAQEBAjAVBgkqhQMHAQIBAgIGCCqFAwcBAQIDA4GEAASBgCB0nQy/Ljva/mRj
w6o+eDKIvnxwYIQB5XCHhZhCpHNZiWcFxFpYXZLWRPKifOxV7NStvqGE1+fkfhBe
btkQu0tdC1XL3LO2Cp/jX16XhW/IP5rKV84qWr1Owy/6tnSsNRb+ez6IttwVvaVV
pA6ONFy9p9gawoC8nitvAVJkWW0PoQoECDVfxzxgMTAHMCIGCCqFAwcBAQECMBYG
ByqFAwICDQAwCwYJKoUDBwECBQEBMIGMMIGJMFswVjEpMCcGCSqGSIb3DQEJARYa
R29zdFIzNDEwLTIwMTJAZXhhbXBsZS5jb20xKTAnBgNVBAMTIEdvc3RSMzQxMC0y
MDEyIDUxMiBiaXRzIGV4Y2hhbmdlAgEBBCowKAQg8C/OcxRR0Uq8nDjHrQlayFb3
WFUZEnEuAKcuG6dTOawEBLhi9hIwOgYJKoZIhvcNAQcBMB8GBiqFAwICFTAVBAiD
1wH+CX6CwgYJKoUDBwECBQEBgAzUvQI4H2zRfgNgdlY=
        """)
        prv_key_our = hexdec("3FC01CDCD4EC5F972EB482774C41E66DB7F380528DFE9E67992BA05AEE462435757530E641077CE587B976C8EEB48C48FD33FD175F0C7DE6A44E014E6BCB074B")[::-1]

        def keker(curve, prv, pub, ukm):
            return kek_34102012256(
                curve,
                prv_unmarshal(prv),
                pub_unmarshal(pub),
                ukm_unmarshal(ukm),
            )

        self.process_cms(
            content_info_raw,
            prv_key_our,
            "id-tc26-gost-3410-12-512-paramSetB",
            keker,
            b"Test message",
        )


@skipIf(not pyderasn_exists, "PyDERASN dependency is required")
class TestR132356510252019(TestCase):
    """Test vectors from Р 1323565.1.025-2019
    """
    def setUp(self):
        self.curve256 = CURVES["id-tc26-gost-3410-2012-256-paramSetA"]
        self.curve512 = CURVES["id-tc26-gost-3410-12-512-paramSetA"]
        self.psk = hexdec("8F5EEF8814D228FB2BBC5612323730CFA33DB7263CC2C0A01A6C6953F33D61D5")[::-1]

        self.ca_prv = prv_unmarshal(hexdec("092F8D059E97E22B90B1AE99F0087FC4D26620B91550CBB437C191005A290810")[::-1])
        self.ca_pub = public_key(self.curve256, self.ca_prv)
        self.ca_cert = Certificate().decod(b64decode("""
MIIB8DCCAZ2gAwIBAgIEAYy6gTAKBggqhQMHAQEDAjA4MQ0wCwYDVQQKEwRUSzI2
MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwHhcNMDEw
MTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA4MQ0wCwYDVQQKEwRUSzI2MScwJQYD
VQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwaDAhBggqhQMHAQEB
ATAVBgkqhQMHAQIBAQEGCCqFAwcBAQICA0MABEAaSoKcjw54UACci6svELNF0IYM
RIW8urUsqamIpoG46XCqrVOuI6Q13N4dwcRsbZdqByf+GC2f5ZfO3baN5bTKo4GF
MIGCMGEGA1UdAQRaMFiAFIDZDPeZ+GZNk1OJjsCecS2npzESoTowODENMAsGA1UE
ChMEVEsyNjEnMCUGA1UEAxMeQ0EgVEsyNjogR09TVCAzNC4xMC0xMiAyNTYtYml0
ggQBjLqBMB0GA1UdDgQWBBSA2Qz3mfhmTZNTiY7AnnEtp6cxEjAKBggqhQMHAQED
AgNBAAgv248F4OeNCkhlzJWec0evHYnMBlSzk1lDm0F875B7CqMrKh2MtJHXenbj
Gc2uRn2IwgmSf/LZDrYsKKqZSxk=
"""))

        self.sender256_prv = prv_unmarshal(hexdec("0B20810E449978C7C3B76C6FF77A16C532421139344A058EF56310B6B6F377E8")[::-1])
        self.sender256_pub = public_key(self.curve256, self.sender256_prv)
        self.sender256_cert = Certificate().decod(b64decode("""
MIIB8zCCAaCgAwIBAgIEAYy6gjAKBggqhQMHAQEDAjA4MQ0wCwYDVQQKEwRUSzI2
MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwHhcNMDEw
MTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA7MQ0wCwYDVQQKEwRUSzI2MSowKAYD
VQQDEyFPUklHSU5BVE9SOiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwaDAhBggqhQMH
AQEBATAVBgkqhQMHAQIBAQEGCCqFAwcBAQICA0MABECWKQ0TYllqg4GmY3tBJiyz
pXUN+aOV9WbmTUinqrmEHP7KCNzoAzFg+04SSQpNNSHpQnm+jLAZhuJaJfqZ6VbT
o4GFMIGCMGEGA1UdAQRaMFiAFIDZDPeZ+GZNk1OJjsCecS2npzESoTowODENMAsG
A1UEChMEVEsyNjEnMCUGA1UEAxMeQ0EgVEsyNjogR09TVCAzNC4xMC0xMiAyNTYt
Yml0ggQBjLqBMB0GA1UdDgQWBBTRnChHSWbQYwnJC62n2zu5Njd03zAKBggqhQMH
AQEDAgNBAB41oijaXSEn58l78y2rhxY35/lKEq4XWZ70FtsNlVxWATyzgO5Wliwn
t1O4GoZsxx8r6T/i7VG65UNmQlwdOKQ=
"""))

        self.recipient256_prv = prv_unmarshal(hexdec("0DC8DC1FF2BC114BABC3F1CA8C51E4F58610427E197B1C2FBDBA4AE58CBFB7CE")[::-1])
        self.recipient256_pub = public_key(self.curve256, self.recipient256_prv)
        self.recipient256_cert = Certificate().decod(b64decode("""
MIIB8jCCAZ+gAwIBAgIEAYy6gzAKBggqhQMHAQEDAjA4MQ0wCwYDVQQKEwRUSzI2
MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwHhcNMDEw
MTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA6MQ0wCwYDVQQKEwRUSzI2MSkwJwYD
VQQDEyBSRUNJUElFTlQ6IEdPU1QgMzQuMTAtMTIgMjU2LWJpdDBoMCEGCCqFAwcB
AQEBMBUGCSqFAwcBAgEBAQYIKoUDBwEBAgIDQwAEQL8nghlzLGMKWHuWhNMPMN5u
L6SkGqRiJ6qZxZb+4dPKbBT9LNVvNKtwUed+BeE5kfqOfolPgFusnL1rnO9yREOj
gYUwgYIwYQYDVR0BBFowWIAUgNkM95n4Zk2TU4mOwJ5xLaenMRKhOjA4MQ0wCwYD
VQQKEwRUSzI2MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1i
aXSCBAGMuoEwHQYDVR0OBBYEFLue+PUb9Oe+pziBU+MvNejjgrzFMAoGCCqFAwcB
AQMCA0EAPP9Oad1/5jwokSjPpccsQ0xCdVYM+mGQ0IbpiZxQj8gnkt8sq4jR6Ya+
I/BDkbZNDNE27TU1p3t5rE9NMEeViA==
"""))

        self.sender512_prv = prv_unmarshal(hexdec("F95A5D44C5245F63F2E7DF8E782C1924EADCB8D06C52D91023179786154CBDB1561B4DF759D69F67EE1FBD5B68800E134BAA12818DA4F3AC75B0E5E6F9256911")[::-1])
        self.sender512_pub = public_key(self.curve512, self.sender512_prv)
        self.sender512_cert = Certificate().decod(b64decode("""
MIICNjCCAeOgAwIBAgIEAYy6hDAKBggqhQMHAQEDAjA4MQ0wCwYDVQQKEwRUSzI2
MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwHhcNMDEw
MTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA7MQ0wCwYDVQQKEwRUSzI2MSowKAYD
VQQDEyFPUklHSU5BVE9SOiBHT1NUIDM0LjEwLTEyIDUxMi1iaXQwgaowIQYIKoUD
BwEBAQIwFQYJKoUDBwECAQIBBggqhQMHAQECAwOBhAAEgYC0i7davCkOGGVcYqFP
tS1fUIROzB0fYARIe0tclTRpare/qzRuVRapqzzO+K21LDpYVfDPs2Sqa13ZN+Ts
/JUlv59qCFB2cYpFyB/0kh4+K79yvz7r8+4WE0EmZf8T3ae/J1Jo6xGunecH1/G4
hMts9HYLnxbwJDMNVGuIHV6gzqOBhTCBgjBhBgNVHQEEWjBYgBSA2Qz3mfhmTZNT
iY7AnnEtp6cxEqE6MDgxDTALBgNVBAoTBFRLMjYxJzAlBgNVBAMTHkNBIFRLMjY6
IEdPU1QgMzQuMTAtMTIgMjU2LWJpdIIEAYy6gTAdBgNVHQ4EFgQUK+l9HAscONGx
zCcRpxRAmFHvlXowCgYIKoUDBwEBAwIDQQAbjA0Q41/rIKOOvjHKsAsoEJM+WJf6
/PKXg2JaStthmw99bdtwwkU/qDbcje2tF6mt+XWyQBXwvfeES1GFY9fJ
"""))

        self.recipient512_prv = prv_unmarshal(hexdec("A50315981F0A7C7FC05B4EB9591A62B1F84BD6FD518ACFCEDF0A7C9CF388D1F18757C056ADA5B38CBF24CDDB0F1519EF72DB1712CEF1920952E94AF1F9C575DC")[::-1])
        self.recipient512_pub = public_key(self.curve512, self.recipient512_prv)
        self.recipient512_cert = Certificate().decod(b64decode("""
MIICNTCCAeKgAwIBAgIEAYy6hTAKBggqhQMHAQEDAjA4MQ0wCwYDVQQKEwRUSzI2
MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwHhcNMDEw
MTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA6MQ0wCwYDVQQKEwRUSzI2MSkwJwYD
VQQDEyBSRUNJUElFTlQ6IEdPU1QgMzQuMTAtMTIgNTEyLWJpdDCBqjAhBggqhQMH
AQEBAjAVBgkqhQMHAQIBAgEGCCqFAwcBAQIDA4GEAASBgKauwGYvUkzz19g0LP/p
zeRdmwy1m+QSy9W5ZrL/AGuJofm2ARjz40ozNbW6bp9hkHu8x66LX7u5zz+QeS2+
X5om18UXriComgO0+qhZbc+Hzu0eQ8FjOd8LpLk3TzzfBltfLOX5IiPLjeum+pSP
0QjoXAVcrop//B4yvZIukvROo4GFMIGCMGEGA1UdAQRaMFiAFIDZDPeZ+GZNk1OJ
jsCecS2npzESoTowODENMAsGA1UEChMEVEsyNjEnMCUGA1UEAxMeQ0EgVEsyNjog
R09TVCAzNC4xMC0xMiAyNTYtYml0ggQBjLqBMB0GA1UdDgQWBBSrXT5VKhm/5uff
kwW0XpG19k6AajAKBggqhQMHAQEDAgNBAAJBpsHRrQKZGb22LOzaReEB8rl2MbIR
ja64NaM5h+cAFoHm6t/k+ziLh2A11rTakR+5of4NQ3EjEhuPtomP2tc=
"""))

    def test_certs(self):
        """Certificates signatures
        """
        for prv, pub, curve, cert in (
                (self.ca_prv, self.ca_pub, self.curve256, self.ca_cert),
                (self.sender256_prv, self.sender256_pub, self.curve256, self.sender256_cert),
                (self.recipient256_prv, self.recipient256_pub, self.curve256, self.recipient256_cert),
                (self.sender512_prv, self.sender512_pub, self.curve512, self.sender512_cert),
                (self.recipient512_prv, self.recipient512_pub, self.curve512, self.recipient512_cert),
        ):
            pub_our = public_key(curve, prv)
            self.assertEqual(pub_our, pub)
            self.assertSequenceEqual(
                pub_marshal(pub_our),
                bytes(OctetString().decod(bytes(
                    cert["tbsCertificate"]["subjectPublicKeyInfo"]["subjectPublicKey"]
                ))),
            )

        for cert in (
                self.ca_cert,
                self.sender256_cert,
                self.recipient256_cert,
                self.sender512_cert,
                self.recipient512_cert,
        ):
            self.assertTrue(verify(
                self.curve256,
                self.ca_pub,
                GOST34112012256(cert["tbsCertificate"].encode()).digest()[::-1],
                bytes(cert["signatureValue"]),
            ))

    def test_signed_with_attrs(self):
        ci = ContentInfo().decod(b64decode("""
MIIENwYJKoZIhvcNAQcCoIIEKDCCBCQCAQExDDAKBggqhQMHAQECAzA7BgkqhkiG
9w0BBwGgLgQsyu7t8vDu6/zt++kg7/Do7OXwIOTr/yDx8vDz6vLz8PsgU2lnbmVk
RGF0YS6gggI6MIICNjCCAeOgAwIBAgIEAYy6hDAKBggqhQMHAQEDAjA4MQ0wCwYD
VQQKEwRUSzI2MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1i
aXQwHhcNMDEwMTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA7MQ0wCwYDVQQKEwRU
SzI2MSowKAYDVQQDEyFPUklHSU5BVE9SOiBHT1NUIDM0LjEwLTEyIDUxMi1iaXQw
gaowIQYIKoUDBwEBAQIwFQYJKoUDBwECAQIBBggqhQMHAQECAwOBhAAEgYC0i7da
vCkOGGVcYqFPtS1fUIROzB0fYARIe0tclTRpare/qzRuVRapqzzO+K21LDpYVfDP
s2Sqa13ZN+Ts/JUlv59qCFB2cYpFyB/0kh4+K79yvz7r8+4WE0EmZf8T3ae/J1Jo
6xGunecH1/G4hMts9HYLnxbwJDMNVGuIHV6gzqOBhTCBgjBhBgNVHQEEWjBYgBSA
2Qz3mfhmTZNTiY7AnnEtp6cxEqE6MDgxDTALBgNVBAoTBFRLMjYxJzAlBgNVBAMT
HkNBIFRLMjY6IEdPU1QgMzQuMTAtMTIgMjU2LWJpdIIEAYy6gTAdBgNVHQ4EFgQU
K+l9HAscONGxzCcRpxRAmFHvlXowCgYIKoUDBwEBAwIDQQAbjA0Q41/rIKOOvjHK
sAsoEJM+WJf6/PKXg2JaStthmw99bdtwwkU/qDbcje2tF6mt+XWyQBXwvfeES1GF
Y9fJMYIBlDCCAZACAQEwQDA4MQ0wCwYDVQQKEwRUSzI2MScwJQYDVQQDEx5DQSBU
SzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQCBAGMuoQwCgYIKoUDBwEBAgOgga0w
GAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTkwMzIw
MTk1NTIyWjAiBgkqhkiG9w0BCWIxFQQTU2lnbmVkIGF0dHIncyB2YWx1ZTBPBgkq
hkiG9w0BCQQxQgRAUdPHEukF5BIfo9DoQIMdnB0ZLkzq0RueEUZSNv07A7C+GKWi
G62fueArg8uPCHPTUN6d/42p33fgMkEwH7f7cDAKBggqhQMHAQEBAgSBgGUnVka8
FvTlClmOtj/FUUacBdE/nEBeMLOO/535VDYrXlftPE6zQf/4ghS7TQG2VRGQ3GWD
+L3+W09A7d5uyyTEbvgtdllUG0OyqFwKmJEaYsMin87SFVs0cn1PGV1fOKeLluZa
bLx5whxd+mzlpekL5i6ImRX+TpERxrA/xSe5
"""))
        _, sd = ci["content"].defined
        content = bytes(sd["encapContentInfo"]["eContent"])
        self.assertEqual(
            content.decode("cp1251"),
            text_type(u"Контрольный пример для структуры SignedData."),
        )
        si = sd["signerInfos"][0]
        self.assertEqual(
            si["digestAlgorithm"]["algorithm"],
            id_tc26_gost3411_2012_512,
        )
        digest = [
            bytes(attr["attrValues"][0].defined[1]) for attr in si["signedAttrs"]
            if attr["attrType"] == id_messageDigest
        ][0]
        self.assertSequenceEqual(digest, GOST34112012512(content).digest())
        self.assertTrue(verify(
            self.curve512,
            self.sender512_pub,
            GOST34112012512(
                SignedAttributes(si["signedAttrs"]).encode()
            ).digest()[::-1],
            bytes(si["signature"]),
        ))

    def test_signed_without_attrs(self):
        ci = ContentInfo().decod(b64decode("""
MIIDAQYJKoZIhvcNAQcCoIIC8jCCAu4CAQExDDAKBggqhQMHAQECAjA7BgkqhkiG
9w0BBwGgLgQsyu7t8vDu6/zt++kg7/Do7OXwIOTr/yDx8vDz6vLz8PsgU2lnbmVk
RGF0YS6gggH3MIIB8zCCAaCgAwIBAgIEAYy6gjAKBggqhQMHAQEDAjA4MQ0wCwYD
VQQKEwRUSzI2MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1i
aXQwHhcNMDEwMTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA7MQ0wCwYDVQQKEwRU
SzI2MSowKAYDVQQDEyFPUklHSU5BVE9SOiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQw
aDAhBggqhQMHAQEBATAVBgkqhQMHAQIBAQEGCCqFAwcBAQICA0MABECWKQ0TYllq
g4GmY3tBJiyzpXUN+aOV9WbmTUinqrmEHP7KCNzoAzFg+04SSQpNNSHpQnm+jLAZ
huJaJfqZ6VbTo4GFMIGCMGEGA1UdAQRaMFiAFIDZDPeZ+GZNk1OJjsCecS2npzES
oTowODENMAsGA1UEChMEVEsyNjEnMCUGA1UEAxMeQ0EgVEsyNjogR09TVCAzNC4x
MC0xMiAyNTYtYml0ggQBjLqBMB0GA1UdDgQWBBTRnChHSWbQYwnJC62n2zu5Njd0
3zAKBggqhQMHAQEDAgNBAB41oijaXSEn58l78y2rhxY35/lKEq4XWZ70FtsNlVxW
ATyzgO5Wliwnt1O4GoZsxx8r6T/i7VG65UNmQlwdOKQxgaIwgZ8CAQEwQDA4MQ0w
CwYDVQQKEwRUSzI2MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1
Ni1iaXQCBAGMuoIwCgYIKoUDBwEBAgIwCgYIKoUDBwEBAQEEQC6jZPA59szL9FiA
0wC71EBE42ap6gKxklT800cu2FvbLu972GJYNSI7+UeanVU37OVWyenEXi2E5HkU
94kBe8Q=
"""))
        _, sd = ci["content"].defined
        content = bytes(sd["encapContentInfo"]["eContent"])
        self.assertEqual(
            content.decode("cp1251"),
            text_type(u"Контрольный пример для структуры SignedData."),
        )
        si = sd["signerInfos"][0]
        self.assertEqual(
            si["digestAlgorithm"]["algorithm"],
            id_tc26_gost3411_2012_256,
        )
        self.assertTrue(verify(
            self.curve256,
            self.sender256_pub,
            GOST34112012256(content).digest()[::-1],
            bytes(si["signature"]),
        ))

    def test_kari_ephemeral(self):
        ci = ContentInfo().decod(b64decode("""
MIIB/gYJKoZIhvcNAQcDoIIB7zCCAesCAQIxggFioYIBXgIBA6CBo6GBoDAXBggq
hQMHAQEBAjALBgkqhQMHAQIBAgEDgYQABIGAe+itJVNbHM35RHfzuwFJPYdPXqtW
8hNEF7Z/XFEE2T71SRkhFX7ozYKQNh/TkVY9D4vG0LnD9Znr/pJyOjpsNb+dPcKX
Kbk/0JQxoPGHxFzASVAFq0ov/yBe2XGFWMeKUqtaAr7SvoYS0oEhT5EuT8BXmecd
nRe7NqOzESpb15ahIgQgsqHxOcdOp03l11S7k3OH1k1HNa5F8m9ctrOzH2846FMw
FwYJKoUDBwEBBwIBMAoGCCqFAwcBAQYCMHYwdDBAMDgxDTALBgNVBAoTBFRLMjYx
JzAlBgNVBAMTHkNBIFRLMjY6IEdPU1QgMzQuMTAtMTIgMjU2LWJpdAIEAYy6hQQw
SxLc18zMwzLwXbcKqYhV/VzsdBgVArOHsSBIbaThJWE7zI37VGPMQJM5VXJ7GVcL
MF0GCSqGSIb3DQEHATAfBgkqhQMHAQEFAgIwEgQQ6EeVlADDCz2cdEWKy+tM94Av
yIFl/Ie4VeFFuczTsMsIaOUEe3Jn9GeVp8hZSj3O2q4hslQ/u/+Gj4QkSHm/M0ih
ITAfBgkqhQMHAQAGAQExEgQQs1t6D3J3WCEvxunnEE15NQ==
"""))
        _, ed = ci["content"].defined
        kari = ed["recipientInfos"][0]["kari"]
        orig_key = kari["originator"]["originatorKey"]
        self.assertEqual(orig_key["algorithm"]["algorithm"], id_tc26_gost3410_2012_512)
        self.assertEqual(
            GostR34102012PublicKeyParameters().decod(
                bytes(orig_key["algorithm"]["parameters"])
            )["publicKeyParamSet"],
            id_tc26_gost3410_2012_512_paramSetA,
        )
        orig_pub = pub_unmarshal(
            bytes(OctetString().decod(bytes(orig_key["publicKey"]))),
        )
        ukm = bytes(kari["ukm"])
        self.assertEqual(
            kari["keyEncryptionAlgorithm"]["algorithm"],
            id_gostr3412_2015_kuznyechik_wrap_kexp15,
        )
        self.assertEqual(
            kari["keyEncryptionAlgorithm"]["parameters"].defined[1]["algorithm"],
            id_tc26_agreement_gost3410_2012_512,
        )
        kexp = bytes(kari["recipientEncryptedKeys"][0]["encryptedKey"])
        keymat = keg(self.curve512, self.recipient512_prv, orig_pub, ukm)
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
            id_gostr3412_2015_kuznyechik_ctracpkm_omac,
        )
        eci_ukm = bytes(
            eci["contentEncryptionAlgorithm"]["parameters"].defined[1]["ukm"]
        )
        self.assertEqual(ed["unprotectedAttrs"][0]["attrType"], id_cms_mac_attr)
        encrypted_mac = bytes(ed["unprotectedAttrs"][0]["attrValues"][0].defined[1])
        encrypted_content = bytes(eci["encryptedContent"])
        cek_enc, cek_mac = kdf_tree_gostr3411_2012_256(
            cek, b"kdf tree", eci_ukm[GOST3412Kuznechik.blocksize // 2:], 2,
        )
        content_and_tag = ctr_acpkm(
            GOST3412Kuznechik,
            GOST3412Kuznechik(cek_enc).encrypt,
            256 * 1024,
            GOST3412Kuznechik.blocksize,
            encrypted_content + encrypted_mac,
            eci_ukm[:GOST3412Kuznechik.blocksize // 2],
        )
        content = content_and_tag[:-GOST3412Kuznechik.blocksize]
        tag_expected = content_and_tag[-GOST3412Kuznechik.blocksize:]
        self.assertSequenceEqual(
            omac(
                GOST3412Kuznechik(cek_mac).encrypt,
                GOST3412Kuznechik.blocksize,
                content,
            ),
            tag_expected,
        )
        self.assertEqual(
            content.decode("cp1251"),
            text_type(u"Контрольный пример для структуры EnvelopedData."),
        )

    def test_kari_static(self):
        ci = ContentInfo().decod(b64decode("""
MIIBawYJKoZIhvcNAQcDoIIBXDCCAVgCAQIxgfehgfQCAQOgQjBAMDgxDTALBgNV
BAoTBFRLMjYxJzAlBgNVBAMTHkNBIFRLMjY6IEdPU1QgMzQuMTAtMTIgMjU2LWJp
dAIEAYy6gqEiBCBvcfyuSF57y8vVyaw8Z0ch3wjC4lPKTrpVRXty4Rhk5DAXBgkq
hQMHAQEHAQEwCgYIKoUDBwEBBgEwbjBsMEAwODENMAsGA1UEChMEVEsyNjEnMCUG
A1UEAxMeQ0EgVEsyNjogR09TVCAzNC4xMC0xMiAyNTYtYml0AgQBjLqDBChPbi6B
krXuLPexPAL2oUGCFWDGQHqINL5ExuMBG7/5XQRqriKARVa0MFkGCSqGSIb3DQEH
ATAbBgkqhQMHAQEFAQEwDgQMdNdCKnYAAAAwqTEDgC9O2bYyTGQJ8WUQGq0zHwzX
L0jFhWHTF1tcAxYmd9pX5i89UwIxhtYqyjX1QHju2g==
"""))
        _, ed = ci["content"].defined
        kari = ed["recipientInfos"][0]["kari"]
        ukm = bytes(kari["ukm"])
        self.assertEqual(
            kari["keyEncryptionAlgorithm"]["algorithm"],
            id_gostr3412_2015_magma_wrap_kexp15,
        )
        self.assertEqual(
            kari["keyEncryptionAlgorithm"]["parameters"].defined[1]["algorithm"],
            id_tc26_agreement_gost3410_2012_256,
        )
        kexp = bytes(kari["recipientEncryptedKeys"][0]["encryptedKey"])
        keymat = keg(
            self.curve256,
            self.recipient256_prv,
            self.sender256_pub,
            ukm,
        )
        kim, kek = keymat[:KEYSIZE], keymat[KEYSIZE:]
        cek = kimp15(
            GOST3412Magma(kek).encrypt,
            GOST3412Magma(kim).encrypt,
            GOST3412Magma.blocksize,
            kexp,
            ukm[24:24 + GOST3412Magma.blocksize // 2],
        )
        eci = ed["encryptedContentInfo"]
        self.assertEqual(
            eci["contentEncryptionAlgorithm"]["algorithm"],
            id_gostr3412_2015_magma_ctracpkm,
        )
        eci_ukm = bytes(
            eci["contentEncryptionAlgorithm"]["parameters"].defined[1]["ukm"]
        )
        content = ctr_acpkm(
            GOST3412Magma,
            GOST3412Magma(cek).encrypt,
            8 * 1024,
            GOST3412Magma.blocksize,
            bytes(eci["encryptedContent"]),
            eci_ukm[:GOST3412Magma.blocksize // 2],
        )
        self.assertEqual(
            content.decode("cp1251"),
            text_type(u"Контрольный пример для структуры EnvelopedData."),
        )

    def test_ktri_256(self):
        ci = ContentInfo().decod(b64decode("""
MIIBlQYJKoZIhvcNAQcDoIIBhjCCAYICAQAxggEcMIIBGAIBADBAMDgxDTALBgNV
BAoTBFRLMjYxJzAlBgNVBAMTHkNBIFRLMjY6IEdPU1QgMzQuMTAtMTIgMjU2LWJp
dAIEAYy6gzAXBgkqhQMHAQEHAgEwCgYIKoUDBwEBBgEEgbcwgbQEMFiMredFR3Mv
3g2wqyVXRnrhYEBMNFaqqgBpHwPQh3bF98tt9HZPxRDCww0OPfxeuTBeMBcGCCqF
AwcBAQEBMAsGCSqFAwcBAgEBAQNDAARAdFJ9ww+3ptvQiaQpizCldNYhl4DB1rl8
Fx/2FIgnwssCbYRQ+UuRsTk9dfLLTGJG3JIEXKFxXWBgOrK965A5pAQg9f2/EHxG
DfetwCe1a6uUDCWD+wp5dYOpfkry8YRDEJgwXQYJKoZIhvcNAQcBMB8GCSqFAwcB
AQUCATASBBDUHNxmVclO/v3OaY9P7jxOgC+sD9CHGlEMRUpfGn6yfFDMExmYeby8
LzdPJe1MkYV0qQgdC1zI3nQ7/4taf+4zRA==
"""))
        _, ed = ci["content"].defined
        ktri = ed["recipientInfos"][0]["ktri"]
        self.assertEqual(
            ktri["keyEncryptionAlgorithm"]["algorithm"],
            id_gostr3412_2015_kuznyechik_wrap_kexp15,
        )
        self.assertEqual(
            ktri["keyEncryptionAlgorithm"]["parameters"].defined[1]["algorithm"],
            id_tc26_agreement_gost3410_2012_256,
        )
        _, encrypted_key = ktri["encryptedKey"].defined
        self.assertEqual(
            encrypted_key["ephemeralPublicKey"]["algorithm"]["algorithm"],
            id_tc26_gost3410_2012_256,
        )
        pub = pub_unmarshal(bytes(OctetString().decod(
            bytes(encrypted_key["ephemeralPublicKey"]["subjectPublicKey"])
        )))
        ukm = bytes(encrypted_key["ukm"])
        kexp = bytes(encrypted_key["encryptedKey"])
        keymat = keg(self.curve256, self.recipient256_prv, pub, ukm)
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
        self.assertEqual(
            content.decode("cp1251"),
            text_type(u"Контрольный пример для структуры EnvelopedData."),
        )

    def test_ktri_512(self):
        ci = ContentInfo().decod(b64decode("""
MIIB5wYJKoZIhvcNAQcDoIIB2DCCAdQCAQAxggFXMIIBUwIBADBAMDgxDTALBgNVBAoTBFRL
MjYxJzAlBgNVBAMTHkNBIFRLMjY6IEdPU1QgMzQuMTAtMTIgMjU2LWJpdAIEAYy6hTAXBgkq
hQMHAQEHAQEwCgYIKoUDBwEBBgIEgfIwge8EKDof9JLTJVuIfP+c+imDCGyOLtAYENkoXpeU
CdiGn0Lt65t3TN9G0bUwgaAwFwYIKoUDBwEBAQIwCwYJKoUDBwECAQIBA4GEAASBgDD9XXHn
0j4EwY3DGB1wzHeThPRDlCwIvpmqWy00QDhS3fLRWiETSe9uMLeg27zI/EiserKMasNZum/i
d09cmP8aTNIDNRtI5H9M0mH7LpEtY8L901MszvOKHLDYdemvz0JUqOvBtvoeQ6sV4Gl45zXx
HTzBWlBw1FLX/ITWLapaBCAa09foTeA+PObBznGuCOPoKy+xz/9IIVmZidI6EYkIrzBZBgkq
hkiG9w0BBwEwGwYJKoUDBwEBBQECMA4EDA4z1UwRL4WYzKFX/oAv8eEX3fWt6hxDpjO0rI7/
CiJ/CwYGCKODJ9h63vAwlsWwcPwAjxcsLvCNlv6i4NqhGTAXBgkqhQMHAQAGAQExCgQIs2DT
LuZ22Yw=
"""))
        _, ed = ci["content"].defined
        ktri = ed["recipientInfos"][0]["ktri"]
        self.assertEqual(
            ktri["keyEncryptionAlgorithm"]["algorithm"],
            id_gostr3412_2015_magma_wrap_kexp15,
        )
        self.assertEqual(
            ktri["keyEncryptionAlgorithm"]["parameters"].defined[1]["algorithm"],
            id_tc26_agreement_gost3410_2012_512,
        )
        _, encrypted_key = ktri["encryptedKey"].defined
        self.assertEqual(
            encrypted_key["ephemeralPublicKey"]["algorithm"]["algorithm"],
            id_tc26_gost3410_2012_512,
        )
        pub = pub_unmarshal(
            bytes(OctetString().decod(
                bytes(encrypted_key["ephemeralPublicKey"]["subjectPublicKey"])
            )),
        )
        ukm = bytes(encrypted_key["ukm"])
        kexp = bytes(encrypted_key["encryptedKey"])
        keymat = keg(self.curve512, self.recipient512_prv, pub, ukm)
        kim, kek = keymat[:KEYSIZE], keymat[KEYSIZE:]
        cek = kimp15(
            GOST3412Magma(kek).encrypt,
            GOST3412Magma(kim).encrypt,
            GOST3412Magma.blocksize,
            kexp,
            ukm[24:24 + GOST3412Magma.blocksize // 2],
        )
        eci = ed["encryptedContentInfo"]
        self.assertEqual(
            eci["contentEncryptionAlgorithm"]["algorithm"],
            id_gostr3412_2015_magma_ctracpkm_omac,
        )
        eci_ukm = bytes(
            eci["contentEncryptionAlgorithm"]["parameters"].defined[1]["ukm"]
        )
        self.assertEqual(ed["unprotectedAttrs"][0]["attrType"], id_cms_mac_attr)
        encrypted_mac = bytes(ed["unprotectedAttrs"][0]["attrValues"][0].defined[1])
        encrypted_content = bytes(eci["encryptedContent"])
        cek_enc, cek_mac = kdf_tree_gostr3411_2012_256(
            cek, b"kdf tree", eci_ukm[GOST3412Magma.blocksize // 2:], 2,
        )
        content_and_tag = ctr_acpkm(
            GOST3412Magma,
            GOST3412Magma(cek_enc).encrypt,
            8 * 1024,
            GOST3412Magma.blocksize,
            encrypted_content + encrypted_mac,
            eci_ukm[:GOST3412Magma.blocksize // 2],
        )
        content = content_and_tag[:-GOST3412Magma.blocksize]
        tag_expected = content_and_tag[-GOST3412Magma.blocksize:]
        self.assertSequenceEqual(
            omac(
                GOST3412Magma(cek_mac).encrypt,
                GOST3412Magma.blocksize,
                content,
            ),
            tag_expected,
        )
        self.assertEqual(
            content.decode("cp1251"),
            text_type(u"Контрольный пример для структуры EnvelopedData."),
        )

    def test_digested256(self):
        ci = ContentInfo().decod(b64decode("""
MH0GCSqGSIb3DQEHBaBwMG4CAQAwCgYIKoUDBwEBAgIwOwYJKoZIhvcNAQcBoC4ELMru7fLw
7uv87fvpIO/w6Ozl8CDk6/8g8fLw8+ry8/D7IERpZ2VzdERhdGEuBCD/esPQYsGkzxZV8uUM
IAWt6SI8KtxBP8NyG8AGbJ8i/Q==
"""))
        _, dd = ci["content"].defined
        eci = dd["encapContentInfo"]
        self.assertSequenceEqual(
            GOST34112012256(bytes(eci["eContent"])).digest(),
            bytes(dd["digest"]),
        )

    def test_digested512(self):
        ci = ContentInfo().decod(b64decode("""
MIGfBgkqhkiG9w0BBwWggZEwgY4CAQAwCgYIKoUDBwEBAgMwOwYJKoZIhvcNAQcBoC4ELMru
7fLw7uv87fvpIO/w6Ozl8CDk6/8g8fLw8+ry8/D7IERpZ2VzdERhdGEuBEDe4VUvcKSRvU7R
FVhFjajXY+nJSUkUsoi3oOeJBnru4PErt8RusPrCJs614ciHCM+ehrC4a+M1Nbq77F/Wsa/v
"""))
        _, dd = ci["content"].defined
        eci = dd["encapContentInfo"]
        self.assertSequenceEqual(
            GOST34112012512(bytes(eci["eContent"])).digest(),
            bytes(dd["digest"]),
        )

    def test_encrypted_kuznechik(self):
        ci = ContentInfo().decod(b64decode("""
MHEGCSqGSIb3DQEHBqBkMGICAQAwXQYJKoZIhvcNAQcBMB8GCSqFAwcBAQUCATASBBBSwX+z
yOEPPuGyfpsRG4AigC/P8ftTdQMStfIThVkE/vpJlwaHgGv83m2bsPayeyuqpoTeEMOaqGcO
0MxHWsC9hQ==
"""))
        _, ed = ci["content"].defined
        eci = ed["encryptedContentInfo"]
        self.assertEqual(
            eci["contentEncryptionAlgorithm"]["algorithm"],
            id_gostr3412_2015_kuznyechik_ctracpkm,
        )
        ukm = bytes(
            eci["contentEncryptionAlgorithm"]["parameters"].defined[1]["ukm"]
        )
        content = ctr_acpkm(
            GOST3412Kuznechik,
            GOST3412Kuznechik(self.psk).encrypt,
            256 * 1024,
            GOST3412Kuznechik.blocksize,
            bytes(eci["encryptedContent"]),
            ukm[:GOST3412Kuznechik.blocksize // 2],
        )
        self.assertEqual(
            content.decode("cp1251"),
            text_type(u"Контрольный пример для структуры EncryptedData."),
        )

    def test_encrypted_magma(self):
        ci = ContentInfo().decod(b64decode("""
MIGIBgkqhkiG9w0BBwagezB5AgEAMFkGCSqGSIb3DQEHATAbBgkqhQMHAQEFAQIwDgQMuncO
u3uYPbI30vFCgC9Nsws4R09yLp6jUtadncWUPZGmCGpPKnXGgNHvEmUArgKJvu4FPHtLkHuL
eQXZg6EZMBcGCSqFAwcBAAYBATEKBAjCbQoH632oGA==
"""))
        _, ed = ci["content"].defined
        eci = ed["encryptedContentInfo"]
        self.assertEqual(
            eci["contentEncryptionAlgorithm"]["algorithm"],
            id_gostr3412_2015_magma_ctracpkm_omac,
        )
        ukm = bytes(
            eci["contentEncryptionAlgorithm"]["parameters"].defined[1]["ukm"]
        )
        self.assertEqual(ed["unprotectedAttrs"][0]["attrType"], id_cms_mac_attr)
        encrypted_mac = bytes(ed["unprotectedAttrs"][0]["attrValues"][0].defined[1])
        cek_enc, cek_mac = kdf_tree_gostr3411_2012_256(
            self.psk, b"kdf tree", ukm[GOST3412Magma.blocksize // 2:], 2,
        )
        content_and_tag = ctr_acpkm(
            GOST3412Magma,
            GOST3412Magma(cek_enc).encrypt,
            8 * 1024,
            GOST3412Magma.blocksize,
            bytes(eci["encryptedContent"]) + encrypted_mac,
            ukm[:GOST3412Magma.blocksize // 2],
        )
        content = content_and_tag[:-GOST3412Magma.blocksize]
        tag_expected = content_and_tag[-GOST3412Magma.blocksize:]
        self.assertSequenceEqual(
            omac(
                GOST3412Magma(cek_mac).encrypt,
                GOST3412Magma.blocksize,
                content,
            ),
            tag_expected,
        )
        self.assertEqual(
            content.decode("cp1251"),
            text_type(u"Контрольный пример для структуры EncryptedData."),
        )
