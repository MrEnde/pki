from asn1crypto._errors import unwrap
from asn1crypto.cms import CMSAttribute
from asn1crypto.x509 import (
    Certificate, Name, Validity, Time, TbsCertificate,
    Version, SignedDigestAlgorithm, Extensions
)
from asn1crypto.keys import (
    PublicKeyAlgorithm, PublicKeyAlgorithmId, PublicKeyInfo,
    ParsableOctetBitString, ECPointBitString
)
from asn1crypto.algos import AlgorithmIdentifier, SignedDigestAlgorithmId
from asn1crypto.core import (
    Any, BitString, Sequence, Integer, ObjectIdentifier, Null, OctetString, OctetBitString, Constructable
)

from asn1crypto import pem

from gostcrypto.gostoid import OBJECT_IDENTIFIER_TC26

from asn1crypto.csr import CertificationRequest, CertificationRequestInfo, CRIAttributes

from asn1crypto.algos import DigestAlgorithmId

from collections import defaultdict

from gostcrypto.gostsignature import MODE_512, new, MODE_256
from gostcrypto.gosthash.gost_34_11_2012 import new as Hash
from pyhanko.sign.general import extract_signer_info

from params_sets import CURVES_R_1323565_1_024_2019
from pki.pdf.pdf_embedded import extract_certs_for_validation
from pki.pdf.reader import GostPdfFileReader
from privatekey import Gost3410Parameters

from pyhanko.sign.validation import validate_pdf_signature

from pki.pdf.general import get_cryptography_hash


class GostPublicKeyAlgorithmId(PublicKeyAlgorithmId):
    _map = {
        '1.2.643.7.1.1.1.1': 'id-tc26-gost3410-12-256',
        '1.2.643.7.1.1.1.2': 'id-tc26-gost3410-12-512',
        '1.2.643.7.1.1.3.2': 'id-tc26-signwithdigest-gost3410-12-256',
        '1.2.643.7.1.1.3.3': 'id-tc26-signwithdigest-gost3410-12-512',
    }


class GostPublicKeyAlgorithm(PublicKeyAlgorithm):
    _fields = [
        ('algorithm', GostPublicKeyAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]
    _oid_specs = {
        'id-tc26-gost3410-12-512': Gost3410Parameters,
        'id-tc26-gost3410-12-256': Gost3410Parameters
    }


class ExtensionPublicKeyInfo(PublicKeyInfo):
    _fields = [
        ('algorithm', GostPublicKeyAlgorithm),
        ('public_key', ParsableOctetBitString),
    ]

    def _public_key_spec(self):
        algorithm = self['algorithm']['algorithm'].native
        return {
            'id-tc26-gost3410-12-512': OctetString,
            'id-tc26-gost3410-12-256': OctetString,
        }[algorithm]

    @property
    def curve(self):
        """
        Returns information about the curve used for an EC key

        :raises:
            ValueError - when the key is not an EC key

        :return:
            A two-element tuple, with the first element being a unicode string
            of "implicit_ca", "specified" or "named". If the first element is
            "implicit_ca", the second is None. If "specified", the second is
            an OrderedDict that is the native version of SpecifiedECDomain. If
            "named", the second is a unicode string of the curve name.
        """
        # if self.algorithm != 'ec':
        #     raise ValueError(unwrap(
        #         '''
        #         Only EC keys have a curve, this key is %s
        #         ''',
        #         self.algorithm.upper()
        #     ))

        params = self['algorithm']['parameters']

        return params

    _spec_callbacks = {
        'public_key': _public_key_spec
    }


class GostSignedDigestAlgorithmId(SignedDigestAlgorithmId):
    _map = {
        '1.2.643.7.1.1.2.2': 'id-tc26-gost3411-12-256',
        '1.2.643.7.1.1.2.3': 'id-tc26-gost3411-12-512',
        '1.2.643.7.1.1.3.2': 'id-tc26-signwithdigest-gost3410-12-256',
        '1.2.643.7.1.1.3.3': 'id-tc26-signwithdigest-gost3410-12-512',
        '1.2.643.7.1.1.1.1': 'id-tc26-gost3410-12-256',
        '1.2.643.7.1.1.1.2': 'id-tc26-gost3410-12-512'
    }

    _reverse_map = {
        'id-tc26-gost3411-12-256': '1.2.643.7.1.1.2.2',
        'id-tc26-gost3411-12-512': '1.2.643.7.1.1.2.3',
        'id-tc26-gost3410-12-256': '1.2.643.7.1.1.1.1',
        'id-tc26-gost3410-12-512': '1.2.643.7.1.1.1.2',
        'id-tc26-signwithdigest-gost3410-12-256': '1.2.643.7.1.1.3.2',
        'id-tc26-signwithdigest-gost3410-12-512': '1.2.643.7.1.1.3.3',
    }


class GostSignedDigestAlgorithm(SignedDigestAlgorithm):
    _fields = [
        ('algorithm', GostSignedDigestAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]

    _oid_specs = {
        'id-tc26-gost3410-12-512': Gost3410Parameters,
        'id-tc26-gost3410-12-256': Gost3410Parameters
    }

    @property
    def parameters(self):
        return self['parameters']

    @property
    def signature_algo(self):
        return self['algorithm'].native

    @property
    def hash_algo(self):
        return self["parameters"]["digest_param_set"].dotted


class ExtensionTbsCertificate(TbsCertificate):
    _fields = [
        ('version', Version, {'explicit': 0, 'default': 'v1'}),
        ('serial_number', Integer),
        ('signature', GostSignedDigestAlgorithm),
        ('issuer', Name),
        ('validity', Validity),
        ('subject', Name),
        ('subject_public_key_info', ExtensionPublicKeyInfo),
        ('issuer_unique_id', OctetBitString, {'implicit': 1, 'optional': True}),
        ('subject_unique_id', OctetBitString, {'implicit': 2, 'optional': True}),
        ('extensions', Extensions, {'explicit': 3, 'optional': True}),
    ]


class GostCertificate(Certificate):
    _fields = [
        ('tbs_certificate', ExtensionTbsCertificate),
        ('signature_algorithm', GostSignedDigestAlgorithm),
        ('signature_value', OctetBitString),
    ]


# certificate_file = input()
# pdf_file = input()
#
# with open("./ca.cer", "rb") as file:
#     der_bytes = file.read()
#     type_name, headers, der_bytes = pem.unarmor(der_bytes)
#
#
# cert = Certificate.load(der_bytes)
# signature: OctetBitString = cert["signature_value"]
# tbs: TbsCertificate = cert["tbs_certificate"]
# tbs_signature: OctetString = tbs["signature"]
# print(tbs_signature)
# signature_algorithm: SignedDigestAlgorithm = cert["signature_algorithm"]
#
# public_key_info: ExtensionPublicKeyInfo = tbs["subject_public_key_info"]
#
# print(public_key_info.native)
# print(signature_algorithm.native)
# public_key = public_key_info["public_key"].native
#
# public_key = cert.public_key['public_key'].native
#
# digest = Hash('streebog256', data=tbs.dump())
#
# signer = new(MODE_256, CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-12-256-paramSetA'])
#
# print(digest.digest().hex())
# print(signer.verify(
#     public_key=public_key,
#     digest=digest.digest(),
#     signature=signature.native
# ))

from asn1crypto.x509 import Certificate
from pprint import pprint

from gostcrypto.gosthash import gost_34_11_2012
from gostcrypto.gostsignature import gost_34_10_2012
from pki.pygost.gost3410 import verify, CURVES, pub_unmarshal

with open("Школа №1788.cert.pem", "rb") as file:
    _, _, der_bytes = pem.unarmor(file.read())

certificate = Certificate.load(der_bytes)
print(certificate["tbs_certificate"]["extensions"].native)
signature = certificate["signature_value"].native
tbs = certificate["tbs_certificate"]
public_info_object = tbs["subject_public_key_info"]
public_key = public_info_object["public_key"].native
parameters = public_info_object.curve
param_set = parameters["public_key_param_set"].native

print(certificate.native)

print(len(public_key))

hasher = gost_34_11_2012.new("streebog512", data=tbs.dump())
digest = hasher.digest()

signer = gost_34_10_2012.new(MODE_512, curve=CURVES_R_1323565_1_024_2019[param_set])

print(verify(CURVES[param_set], pub_unmarshal(public_key), digest[::-1], signature))
print(signer.verify(public_key, digest[::-1], signature))

# with open("signed_file.pdf", "rb") as signed_document:
#     print()
#     reader = GostPdfFileReader(signed_document)
#     embedded_signature = reader.embedded_signatures[0]
#
#     print(embedded_signature)
#     print(embedded_signature.external_md_algorithm)
#     pprint(embedded_signature.signed_data)
#
#     # status = validate_pdf_signature(embedded_signature)
#     #
#     # print(status.pretty_print_details())
#     # print(embedded_signature.external_digest)
#
#     embedded_signature = reader.embedded_signatures[0]
#     signed_data = embedded_signature.signed_data
#
#     signer_info = extract_signer_info(signed_data)
#     cert_info = extract_certs_for_validation(signed_data)
#     cert = cert_info.signer_cert
#     other_certs = cert_info.other_certs
#
#     signature_algorithm: SignedDigestAlgorithm = \
#         signer_info['signature_algorithm']
#     mechanism = signature_algorithm['algorithm'].native
#     md_algorithm = signer_info['digest_algorithm']['algorithm'].native
#     eci = signed_data['encap_content_info']
#     expected_content_type = eci['content_type'].native
#     digest_algorithms = signed_data["digest_algorithms"]
#
#     pprint(cert.native)
#
#     print(mechanism)
#     print(md_algorithm)
#     print(digest_algorithms.native)
#
#     print(signature_algorithm.native)
#
#     pprint(cert.native)
#
#     signed_attrs = signer_info['signed_attrs'].untag()
#     signed_data = signed_attrs.dump()
#
#     root = embedded_signature.signed_data['certificates'][0]
#     root = Certificate.load(root.dump())
#
#     public_key = root.public_key['public_key'].native
#
#     digest = Hash(get_cryptography_hash(md_algorithm), data=root['tbs_certificate'].dump())
#
#     # digest = embedded_signature.compute_digest()
#
#     signer = new(MODE_512, CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-12-512-paramSetA'])
#
#     print(signer.verify(
#         public_key=public_key,
#         digest=digest.digest(),
#         signature=root['signature_value'].native
#     ))
#
#     public = cert.public_key

# with open("ca.cer", "rb") as file:
#
#
#     signature_value = cert['signature_value'].native
#
#     signer = new(MODE_256, CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-12-256-paramSetA'])
#
#     cert_digest = Hash("streebog256", data=cert['tbs_certificate'].dump())
#
#     print()
#
#     print(signer.verify(
#         public_key=public['public_key'].native,
#         digest=cert_digest.digest(),
#         signature=signature_value
#     ))
#
#     print("asdasd")
#
#     digest = Hash(get_cryptography_hash(md_algorithm), data=signed_data)
#
#     curve = Gost3410Parameters.load(public["algorithm"]["parameters"].dump())["public_key_param_set"].native
#
#     signer = new(MODE_512, CURVES_R_1323565_1_024_2019[curve])
#     print(
#         signer.verify(
#             public["public_key"].native,
#             digest.digest(),
#             signer_info["signature"].native
#         )
#     )
