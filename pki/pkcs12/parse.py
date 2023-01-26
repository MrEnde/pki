from asn1crypto.cms import EncryptedData
from asn1crypto.pkcs12 import Pfx
from asn1crypto.core import OctetString
from oscrypto.asymmetric import load_private_key
from oscrypto._types import type_name, str_cls, byte_cls, int_types
from oscrypto._errors import pretty_message

from main import GostCertificate
from pkcs12.safe_content import parse_safe_contents, _decrypt_encrypted_data
from privatekey import ExtendPrivateKeyInfo


def load_key_and_certificates(data, password=None) -> tuple[ExtendPrivateKeyInfo, GostCertificate, tuple[GostCertificate]]:
    """
    Parses a PKCS#12 ANS.1 DER-encoded structure and extracts certs and keys

    :param data:
        A byte string of a DER-encoded PKCS#12 file

    :param password:
        A byte string of the password to any encrypted data

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by one of the OS decryption functions

    :return:
        A three-element tuple of:
         1. An asn1crypto.keys.PrivateKeyInfo object
         2. An asn1crypto.x509.Certificate object
         3. A list of zero or more asn1crypto.x509.Certificate objects that are
            "extra" certificates, possibly intermediates from the cert chain
    """

    return _parse_pkcs12(data, password, load_private_key)


def _parse_pkcs12(data, password, load_private_key):
    """
    Parses a PKCS#12 ANS.1 DER-encoded structure and extracts certs and keys

    :param data:
        A byte string of a DER-encoded PKCS#12 file

    :param password:
        A byte string of the password to any encrypted data

    :param load_private_key:
        A callable that will accept a byte string and return an
        oscrypto.asymmetric.PrivateKey object

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by one of the OS decryption functions

    :return:
        A three-element tuple of:
         1. An asn1crypto.keys.PrivateKeyInfo object
         2. An asn1crypto.x509.Certificate object
         3. A list of zero or more asn1crypto.x509.Certificate objects that are
            "extra" certificates, possibly intermediates from the cert chain
    """

    if not isinstance(data, byte_cls):
        raise TypeError(pretty_message(
            '''
            data must be a byte string, not %s
            ''',
            type_name(data)
        ))

    if password is not None:
        if not isinstance(password, byte_cls):
            raise TypeError(pretty_message(
                '''
                password must be a byte string, not %s
                ''',
                type_name(password)
            ))
    else:
        password = b''

    certs = {}
    private_keys = {}

    pfx = Pfx.load(data)

    auth_safe = pfx['auth_safe']
    if auth_safe['content_type'].native != 'data':
        raise ValueError(pretty_message(
            '''
            Only password-protected PKCS12 files are currently supported
            '''
        ))
    authenticated_safe = pfx.authenticated_safe

    # mac_data = pfx['mac_data']
    # if mac_data:
    #     mac_algo = mac_data['mac']['digest_algorithm']['algorithm'].native
    #     key_length = {
    #         'sha1': 20,
    #         'sha224': 28,
    #         'sha256': 32,
    #         'sha384': 48,
    #         'sha512': 64,
    #         'sha512_224': 28,
    #         'sha512_256': 32,
    #     }[mac_algo]
    #     mac_key = pkcs12_kdf(
    #         mac_algo,
    #         password,
    #         mac_data['mac_salt'].native,
    #         mac_data['iterations'].native,
    #         key_length,
    #         3  # ID 3 is for generating an HMAC key
    #     )
    #     hash_mod = getattr(hashlib, mac_algo)
    #     computed_hmac = hmac.new(mac_key, auth_safe['content'].contents, hash_mod).digest()
    #     stored_hmac = mac_data['mac']['digest'].native
    #     if not constant_compare(computed_hmac, stored_hmac):
    #         raise ValueError('Password provided is invalid')

    for content_info in authenticated_safe:
        content = content_info['content']

        if isinstance(content, OctetString):
            parse_safe_contents(content.native, certs, private_keys, password, load_private_key)

        elif isinstance(content, EncryptedData):
            encrypted_content_info = content['encrypted_content_info']

            encryption_algorithm_info = encrypted_content_info['content_encryption_algorithm']

            encrypted_content = encrypted_content_info['encrypted_content'].native

            decrypted_content = _decrypt_encrypted_data(encryption_algorithm_info, encrypted_content, password)

            parse_safe_contents(decrypted_content, certs, private_keys, password, load_private_key)

        else:
            raise ValueError(pretty_message(
                '''
                Public-key-based PKCS12 files are not currently supported
                '''
            ))

    key_fingerprints = set(private_keys.keys())
    cert_fingerprints = set(certs.keys())

    common_fingerprints = sorted(list(key_fingerprints & cert_fingerprints))

    key = None
    cert = None
    other_certs = []

    if len(common_fingerprints) >= 1:
        fingerprint = common_fingerprints[0]

        key = private_keys[fingerprint]
        cert = certs[fingerprint]
        other_certs = [certs[f] for f in certs if f != fingerprint]
        return key, cert, other_certs

    if len(private_keys) > 0:
        first_key = sorted(list(private_keys.keys()))[0]
        key = private_keys[first_key]

    if len(certs) > 0:
        # first_key = sorted(list(certs.keys()))[0]
        first_key = list(certs.keys())[0]
        cert = certs[first_key]

        del certs[first_key]

    if len(certs) > 0:
        other_certs = sorted(list(certs.values()), key=lambda c: c.subject.human_friendly)

    return key, cert, other_certs
