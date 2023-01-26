from asn1crypto.core import (
    Any, OctetString, Sequence, Integer, ObjectIdentifier
)

from asn1crypto.algos import (
    EncryptionAlgorithm, EncryptionAlgorithmId, Rc2Params, Rc5Params,
    CcmParams, Pbes1Params, RSAESOAEPParams
)
from asn1crypto.cms import KdfAlgorithm
from asn1crypto.keys import EncryptedPrivateKeyInfo

# EncryptionAlgorithmId._map["1.2.643.2.2.21"] = "gost_28147"
EncryptionAlgorithmId._map["1.2.840.113549.1.12.1.80"] = "gost-wrap-key"


class PrivateKeyOID(Sequence):
    _fields = [
        ("parameters", ObjectIdentifier),
        ("digest", ObjectIdentifier)
    ]


class ExportBlobContentEncryptionKey(Sequence):
    _fields = [
        ("enc", OctetString),
        ("mac", OctetString)
    ]


class InnerExportBlob(Sequence):
    _fields = [
        ("ukm", OctetString),
        ("cek", ExportBlobContentEncryptionKey),
        ("oids", Any)
    ]


class ExportBlob(Sequence):
    _fields = [
        ("value", InnerExportBlob),
        ("not_used", OctetString)
    ]


class Blob(Sequence):
    _fields = [
        ("version", Integer),
        ("not_used", Any),
        ("value", OctetString)
    ]


class ExtendEncryptionAlgorithm(EncryptionAlgorithm):
    _fields = [
        ('algorithm', EncryptionAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]

    _oid_pair = ('algorithm', 'parameters')
    _oid_specs = {
        'des': OctetString,
        'tripledes_3key': OctetString,
        'rc2': Rc2Params,
        'rc5': Rc5Params,
        'aes128_cbc': OctetString,
        'aes192_cbc': OctetString,
        'aes256_cbc': OctetString,
        'aes128_ofb': OctetString,
        'aes192_ofb': OctetString,
        'aes256_ofb': OctetString,
        # From RFC5084
        'aes128_ccm': CcmParams,
        'aes192_ccm': CcmParams,
        'aes256_ccm': CcmParams,
        # From PKCS#5
        'pbes1_md2_des': Pbes1Params,
        'pbes1_md5_des': Pbes1Params,
        'pbes1_md2_rc2': Pbes1Params,
        'pbes1_md5_rc2': Pbes1Params,
        'pbes1_sha1_des': Pbes1Params,
        'pbes1_sha1_rc2': Pbes1Params,
        # From PKCS#12
        'pkcs12_sha1_rc4_128': Pbes1Params,
        'pkcs12_sha1_rc4_40': Pbes1Params,
        'pkcs12_sha1_tripledes_3key': Pbes1Params,
        'pkcs12_sha1_tripledes_2key': Pbes1Params,
        'pkcs12_sha1_rc2_128': Pbes1Params,
        'pkcs12_sha1_rc2_40': Pbes1Params,
        # PKCS#1 v2.2
        'rsaes_oaep': RSAESOAEPParams,

        'gost-wrap-key': Pbes1Params
    }

    @property
    def encryption_cipher(self):
        encryption_algo = self['algorithm'].native

        if encryption_algo == "gost-wrap-key":
            return "gost-wrap-key"

        if encryption_algo == "gost_28147":
            return "gost"

        return super().encryption_cipher

    @property
    def key_length(self):
        encryption_algo = self['algorithm'].native

        if encryption_algo == "gost_28147":
            return 32

        return super().key_length


class Pbes2Params(Sequence):
    _fields = [
        ('key_derivation_func', KdfAlgorithm),
        ('encryption_scheme', ExtendEncryptionAlgorithm),
    ]


# ExtendEncryptionAlgorithm._oid_specs['gost-wrap-key'] = Pbes2Params
