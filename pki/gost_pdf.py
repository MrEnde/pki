from typing import Optional

from asn1crypto import keys, x509, cms
from asn1crypto.algos import SignedDigestAlgorithm, Gost3410Parameters, SignedDigestAlgorithmId
from gostcrypto import gosthash, gostsignature

from pyhanko.sign import signers
from pyhanko.sign.signers.pdf_cms import format_attributes

from pyhanko_certvalidator.registry import CertificateStore, SimpleCertificateStore

from pki.pdf.general import get_cryptography_hash, get_signature_mode
from pki.pdf.reader import GostPdfFileReader


def get_curve_from_parameters(parameters: Gost3410Parameters):
    mapped_oid: SignedDigestAlgorithmId = parameters["public_key_param_set"]

    return gostsignature.CURVES_R_1323565_1_024_2019[mapped_oid.native]


class GostSigner(signers.Signer):
    def __init__(self, signing_cert: x509.Certificate,
                 signing_key: keys.PrivateKeyInfo,
                 cert_registry: CertificateStore,
                 signature_mechanism: SignedDigestAlgorithm = None,
                 prefer_pss=False, embed_roots=True, attribute_certs=None):
        self.signing_cert = signing_cert
        self.signing_key = signing_key
        self.cert_registry = cert_registry
        self.signature_mechanism = signature_mechanism
        if attribute_certs is not None:
            self.attribute_certs = list(attribute_certs)
        super().__init__(prefer_pss=prefer_pss, embed_roots=embed_roots)

    # @classmethod
    # def load_from_pfx(cls, pfx_file: str, password: str):
    #     with open(pfx_file, "rb") as file:
    #         private_key, public_cert, other_certs = load_key_and_certificates(
    #             file.read(), password.encode("utf-8")
    #         )
    #
    #     # validator = CertificateValidator(other_certs[0])
    #     # validator.validate_usage({"key_encipherment"})
    #
    #     certificate_store = SimpleCertificateStore()
    #
    #     # certificate_store.register_multiple(other_certs)
    #
    #     return cls(
    #         public_cert, private_key, certificate_store
    #     )

    async def unsigned_attrs(self, digest_algorithm: str,
                             signature: bytes,
                             signed_attrs: cms.CMSAttributes,
                             timestamper=None, dry_run=False) -> Optional[cms.CMSAttributes]:
        provs = self._unsigned_attr_providers(
            signature=signature,
            signed_attrs=signed_attrs,
            digest_algorithm=digest_algorithm,
            timestamper=timestamper
        )
        attrs = await format_attributes(list(provs), dry_run=dry_run)
        return attrs or None

    def get_signature_mechanism(self, digest_algorithm=None) -> SignedDigestAlgorithm:
        if self.signature_mechanism is not None:
            return self.signature_mechanism

        public_key = self.signing_cert.public_key

        algorithm = public_key.algorithm
        parameters = public_key["algorithm"]["parameters"]

        structure = {
            'algorithm': algorithm,
            'parameters': parameters
        }

        return SignedDigestAlgorithm(structure)

    def sign_raw(self, data: bytes, digest_algorithm: str) -> bytes:
        """
        Synchronous raw signature implementation.

        :param data:
            Data to be signed.
        :param digest_algorithm:
            Digest algorithm to use.
        :return:
            Raw signature encoded according to the conventions of the
            signing algorithm used.
        """
        signature_mechanism = self.get_signature_mechanism(digest_algorithm)

        signature_algorithm = signature_mechanism.signature_algo

        curve = get_curve_from_parameters(signature_mechanism["parameters"])

        signer = gostsignature.new(get_signature_mode(signature_algorithm), curve)
        hasher = gosthash.new(get_cryptography_hash(signature_mechanism.hash_algo), data=data)

        digest = hasher.digest()

        return bytes(signer.sign(self.signing_key["private_key"].native, digest[::-1]))

    async def async_sign_raw(self, data: bytes, digest_algorithm: str, dry_run=False) -> bytes:
        if dry_run:
            algorithm = self.get_signature_mechanism(digest_algorithm).signature_algo

            return bytes(32 if "256" in algorithm else 64)

        return self.sign_raw(data, digest_algorithm)
