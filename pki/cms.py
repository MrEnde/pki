from asn1crypto.cms import SignedData, CMSVersion, RevocationInfoChoices, CertificateChoices, ExtendedCertificate, \
    AttributeCertificateV1, AttributeCertificateV2, OtherCertificateFormat, SignerInfo, SignerIdentifier, CMSAttributes, \
    EncapsulatedContentInfo, ContentInfo, ExtendedCertificateInfo, CertificateSet, DigestAlgorithms
from asn1crypto.core import SetOf, Sequence, OctetBitString, Integer, OctetString, Choice
from asn1crypto.x509 import Attributes

from main import GostSignedDigestAlgorithm, GostCertificate


class GostSignerInfo(SignerInfo):
    _fields = [
        ('version', CMSVersion),
        ('sid', SignerIdentifier),
        ('digest_algorithm', GostSignedDigestAlgorithm),
        ('signed_attrs', CMSAttributes, {'implicit': 0, 'optional': True}),
        ('signature_algorithm', GostSignedDigestAlgorithm),
        ('signature', OctetString),
        ('unsigned_attrs', CMSAttributes, {'implicit': 1, 'optional': True}),
    ]


class SignerInfos(SetOf):
    _child_spec = GostSignerInfo


class GostExtendedCertificateInfo(ExtendedCertificateInfo):
    _fields = [
        ('version', Integer),
        ('certificate', GostCertificate),
        ('attributes', Attributes),
    ]


class GostCertificateChoices(CertificateChoices):
    _alternatives = [
        ('certificate', GostCertificate),
        ('extended_certificate', ExtendedCertificate, {'implicit': 0}),
        ('v1_attr_cert', AttributeCertificateV1, {'implicit': 1}),
        ('v2_attr_cert', AttributeCertificateV2, {'implicit': 2}),
        ('other', OtherCertificateFormat, {'implicit': 3}),
    ]


class GostCertificateSet(CertificateSet):
    _child_spec = GostCertificateChoices


class GostDigestAlgorithms(DigestAlgorithms):
    _child_spec = GostSignedDigestAlgorithm


class GostSignedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('digest_algorithms', GostDigestAlgorithms),
        ('encap_content_info', None),
        ('certificates', GostCertificateSet, {'implicit': 0, 'optional': True}),
        ('crls', RevocationInfoChoices, {'implicit': 1, 'optional': True}),
        ('signer_infos', SignerInfos),
    ]

    def _encap_content_info_spec(self):
        # If the encap_content_info is version v1, then this could be a PKCS#7
        # structure, or a CMS structure. CMS wraps the encoded value in an
        # Octet String tag.

        # If the version is greater than 1, it is definite CMS
        if self['version'].native != 'v1':
            return EncapsulatedContentInfo

        # Otherwise, the ContentInfo spec from PKCS#7 will be compatible with
        # CMS v1 (which only allows Data, an Octet String) and PKCS#7, which
        # allows Any
        return ContentInfo

    _spec_callbacks = {
        'encap_content_info': _encap_content_info_spec
    }
