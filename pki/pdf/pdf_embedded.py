from copy import copy
from io import BytesIO, BufferedReader
from typing import Union, IO, Iterable, Tuple

from asn1crypto import x509, cms, tsp
from pyhanko.pdf_utils import misc
from pyhanko.pdf_utils.misc import chunk_stream
from pyhanko.sign.ades.report import AdESIndeterminate
from pyhanko.sign.general import extract_certificate_info, CMSExtractionError, extract_signer_info, \
    NonexistentAttributeError, MultivaluedAttributeError, find_unique_cms_attribute, SignedDataCerts, \
    match_issuer_serial, SigningError, get_pyca_cryptography_hash
from pyhanko.sign.validation import EmbeddedPdfSignature, errors

from pki.pdf.general import get_cryptography_hash

from gostcrypto import gosthash

from cryptography.hazmat.primitives import hashes


def check_ess_certid(cert: x509.Certificate,
                     certid: Union[tsp.ESSCertID, tsp.ESSCertIDv2]):
    """
    Match an ``ESSCertID`` value against a certificate.

    :param cert:
        The certificate to match against.
    :param certid:
        The ``ESSCertID`` value.
    :return:
        ``True`` if the ``ESSCertID`` matches the certificate,
        ``False`` otherwise.
    """
    hash_algo = certid['hash_algorithm']['algorithm'].native

    try:
        hash_spec = get_cryptography_hash(hash_algo)
        md = gosthash.new(hash_spec)
        md.update(cert.dump())
        digest_value = md.digest()
    except SigningError:
        hash_spec = get_pyca_cryptography_hash(hash_algo)
        md = hashes.Hash(hash_spec)
        md.update(cert.dump())
        digest_value = md.finalize()

    expected_digest_value = certid['cert_hash'].native

    if digest_value != expected_digest_value:
        return False
    expected_issuer_serial: tsp.IssuerSerial = certid['issuer_serial']
    return (
            not expected_issuer_serial or
            match_issuer_serial(expected_issuer_serial, cert)
    )


def _check_signing_certificate(cert: x509.Certificate,
                               signed_attrs: cms.CMSAttributes):
    def _grab(attr_name, cls):
        try:
            value = find_unique_cms_attribute(signed_attrs, attr_name)
            # reencode the attribute to avoid accidentally tripping the
            # _is_mutated logic on the parent object (is important to preserve
            # the state of the signed attributes)
            return cls.load(value.dump())
        except NonexistentAttributeError:
            return None
        except MultivaluedAttributeError as e:
            raise errors.SignatureValidationError(
                "Wrong cardinality for signing certificate attribute"
            ) from e

    attr = _grab('signing_certificate_v2', tsp.SigningCertificateV2)
    if attr is None:
        attr = _grab('signing_certificate', tsp.SigningCertificate)

    if attr is None:
        # if neither attr is present -> no constraints
        return

    # we only care about the first value, the others limit the set of applicable
    # CA certs
    certid = attr['certs'][0]

    if not check_ess_certid(cert, certid):
        raise errors.SignatureValidationError(
            f"Signing certificate attribute does not match selected "
            f"signer's certificate for subject"
            f"\"{cert.subject.human_friendly}\".",
            ades_subindication=AdESIndeterminate.NO_SIGNING_CERTIFICATE_FOUND
        )


def extract_certs_for_validation(signed_data: cms.SignedData) \
        -> SignedDataCerts:
    """
    Extract certificates from a CMS signed data object for validation purposes,
    identifying the signer's certificate in accordance with ETSI EN 319 102-1,
    5.2.3.4.

    :param signed_data:
        The CMS payload.
    :return:
        The extracted certificates.
    """

    try:
        cert_info = extract_certificate_info(signed_data)
        cert = cert_info.signer_cert
    except CMSExtractionError:
        raise errors.SignatureValidationError(
            'signer certificate not included in signature',
            ades_subindication=AdESIndeterminate.NO_SIGNING_CERTIFICATE_FOUND
        )
    signer_info = extract_signer_info(signed_data)
    signed_attrs = signer_info['signed_attrs']
    # check the signing-certificate or signing-certificate-v2 attr
    _check_signing_certificate(cert, signed_attrs)
    return cert_info


def chunked_digest(temp_buffer: bytearray, stream, md, max_read=None):
    for chunk in chunk_stream(temp_buffer, stream, max_read=max_read):
        md.update(bytes(chunk))


def byte_range_digest(stream: IO, byte_range: Iterable[int],
                      md_algorithm: str,
                      chunk_size=misc.DEFAULT_CHUNK_SIZE) -> Tuple[int, bytes]:
    """
    Internal API to compute byte range digests. Potentially dangerous if used
    without due caution.

    :param stream:
        Stream over which to compute the digest. Must support seeking and
        reading.
    :param byte_range:
        The byte range, as a list of (offset, length) pairs, flattened.
    :param md_algorithm:
        The message digest algorithm to use.
    :param chunk_size:
        The I/O chunk size to use.
    :return:
        A tuple of the total digested length, and the actual digest.
    """
    md_spec = get_cryptography_hash(md_algorithm)
    md = gosthash.new(md_spec)

    # compute the digest
    # here, we allow arbitrary byte ranges
    # for the coverage check, we'll impose more constraints
    total_len = 0
    chunk_buf = bytearray(chunk_size)
    for lo, chunk_len in misc.pair_iter(byte_range):
        stream.seek(lo)
        chunked_digest(chunk_buf, stream, md, max_read=chunk_len)
        total_len += chunk_len

    return total_len, md.digest()


class GostEmbeddedPdfSignature(EmbeddedPdfSignature):
    def _init_cert_info(self):
        if self._sd_cert_info is not None:
            return
        self._sd_cert_info = extract_certs_for_validation(self.signed_data)

    def compute_digest(self) -> bytes:
        """
        Compute the ``/ByteRange`` digest of this signature.
        The result will be cached.

        :return:
            The digest value.
        """
        if self.external_digest is not None:
            return self.external_digest

        self.total_len, digest = byte_range_digest(
            self.reader.stream, byte_range=self.byte_range,
            md_algorithm=self.external_md_algorithm,
        )
        self.external_digest = digest
        return digest
