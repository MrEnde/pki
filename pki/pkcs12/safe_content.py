import asn1
from asn1crypto.core import OctetString, ObjectIdentifier, Any
from asn1crypto.keys import PrivateKeyInfo
from oscrypto._asymmetric import crypto_funcs
from oscrypto._pkcs12 import pkcs12_kdf
from oscrypto._pkcs5 import pbkdf2
from asn1crypto.pkcs12 import (
    SafeContents, EncryptedPrivateKeyInfo, CertBag, Integer
)
from oscrypto.kdf import pbkdf1

from main import GostCertificate, ExtensionPublicKeyInfo

from oscrypto._types import type_name, byte_cls
from oscrypto._errors import pretty_message
from oscrypto.symmetric import (
    rc2_cbc_pkcs5_decrypt, rc4_decrypt, des_cbc_pkcs5_decrypt,
    tripledes_cbc_pkcs5_decrypt, aes_cbc_pkcs7_decrypt
)

import hashlib

from pkcs12.container.encryption import extract_private_key
from pkcs12.types import ExtendEncryptionAlgorithm, Blob, ExportBlob, PrivateKeyOID
from pygost.gost28147 import cfb_decrypt, DEFAULT_SBOX, ecb_decrypt

from pygost.gost28147 import cfb_decrypt, DEFAULT_SBOX, ecb_decrypt
from pygost.kdf import kdf_gostr3411_2012_256
from pygost.gost28147 import encrypt

from privatekey import ExtendPrivateKeyInfo, PrivateKeyAlgorithm, PrivateKeyAlgorithmId


def _decrypt_encrypted_data(encryption_algorithm_info, encrypted_content, password):
    """
    Decrypts encrypted ASN.1 data

    :param encryption_algorithm_info:
        An instance of asn1crypto.pkcs5.Pkcs5EncryptionAlgorithm

    :param encrypted_content:
        A byte string of the encrypted content

    :param password:
        A byte string of the encrypted content's password

    :return:
        A byte string of the decrypted plaintext
    """

    encryption_cipher = encryption_algorithm_info.encryption_cipher

    if encryption_cipher == "gost-wrap-key":
        return extract_private_key(encryption_algorithm_info, encrypted_content, password)

    decrypt_func = crypto_funcs[encryption_cipher]

    # Modern, PKCS#5 PBES2-based encryption
    if encryption_algorithm_info.kdf == 'pbkdf2':

        if encryption_cipher == 'rc5':
            raise ValueError(pretty_message(
                '''
                PBES2 encryption scheme utilizing RC5 encryption is not supported
                '''
            ))

        enc_key = pbkdf2(
            encryption_algorithm_info.kdf_hmac,
            password,
            encryption_algorithm_info.kdf_salt,
            encryption_algorithm_info.kdf_iterations,
            encryption_algorithm_info.key_length
        )
        enc_iv = encryption_algorithm_info.encryption_iv

        private_key = decrypt_func(enc_key, encrypted_content, enc_iv)

    elif encryption_algorithm_info.kdf == 'pbkdf1':
        derived_output = pbkdf1(
            encryption_algorithm_info.kdf_hmac,
            password,
            encryption_algorithm_info.kdf_salt,
            encryption_algorithm_info.kdf_iterations,
            encryption_algorithm_info.key_length + 8
        )
        enc_key = derived_output[0:8]
        enc_iv = derived_output[8:16]

        private_key = decrypt_func(enc_key, encrypted_content, enc_iv)

    elif encryption_algorithm_info.kdf == 'pkcs12_kdf':
        enc_key = pkcs12_kdf(
            encryption_algorithm_info.kdf_hmac,
            password,
            encryption_algorithm_info.kdf_salt,
            encryption_algorithm_info.kdf_iterations,
            encryption_algorithm_info.key_length,
            1  # ID 1 is for generating a key
        )

        # Since RC4 is a stream cipher, we don't use an IV
        if encryption_cipher == 'rc4':
            private_key = decrypt_func(enc_key, encrypted_content)

        else:
            enc_iv = pkcs12_kdf(
                encryption_algorithm_info.kdf_hmac,
                password,
                encryption_algorithm_info.kdf_salt,
                encryption_algorithm_info.kdf_iterations,
                encryption_algorithm_info.encryption_block_size,
                2  # ID 2 is for generating an IV
            )
            private_key = decrypt_func(enc_key, encrypted_content, enc_iv)

    return private_key


def fingerprint(key_object, load_private_key):
    """
    Returns a fingerprint used for correlating public keys and private keys

    :param key_object:
        An asn1crypto.keys.PrivateKeyInfo or asn1crypto.keys.PublicKeyInfo

    :raises:
        ValueError - when the key_object is not of the proper type

    :return:
        A byte string fingerprint
    """

    if isinstance(key_object, PrivateKeyInfo):
        to_hash = key_object['private_key'].dump()

        return hashlib.sha1(to_hash).digest()

    if isinstance(key_object, ExtensionPublicKeyInfo):
        to_hash = key_object['public_key'].dump()

        return hashlib.sha1(to_hash).digest()

    raise ValueError(pretty_message(
        '''
        key_object must be an instance of the
        asn1crypto.keys.PrivateKeyInfo or asn1crypto.keys.PublicKeyInfo
        classes, not %s
        ''',
        type_name(key_object)
    ))


def parse_safe_contents(safe_contents, certs, private_keys, password, load_private_key):
    """
    Parses a SafeContents PKCS#12 ANS.1 structure and extracts certs and keys

    :param safe_contents:
        A byte string of ber-encoded SafeContents, or a asn1crypto.pkcs12.SafeContents
        parsed object

    :param certs:
        A dict to store certificates in

    :param keys:
        A dict to store keys in

    :param password:
        A byte string of the password to any encrypted data

    :param load_private_key:
        A callable that will accept a byte string and return an
        oscrypto.asymmetric.PrivateKey object
    """

    if isinstance(safe_contents, byte_cls):
        safe_contents = SafeContents.load(safe_contents)

    for safe_bag in safe_contents:
        bag_value = safe_bag['bag_value']

        if isinstance(bag_value, CertBag):
            if bag_value['cert_id'].native == 'x509':
                cert = bag_value['cert_value'].parsed

                cert = GostCertificate.load(
                    cert.dump()
                )

                public_key_info = cert['tbs_certificate']['subject_public_key_info']
                certs[fingerprint(public_key_info, None)] = cert

        elif isinstance(bag_value, PrivateKeyInfo):
            private_keys[fingerprint(bag_value, load_private_key)] = bag_value

        elif isinstance(bag_value, EncryptedPrivateKeyInfo):
            encryption_algorithm_info = ExtendEncryptionAlgorithm.load(
                bag_value['encryption_algorithm'].dump()
            )
            encrypted_key_bytes = bag_value['encrypted_data'].native
            decrypted_key_bytes = _decrypt_encrypted_data(encryption_algorithm_info, encrypted_key_bytes, password)

            private_key = ExtendPrivateKeyInfo.load(decrypted_key_bytes)
            private_keys[fingerprint(private_key, load_private_key)] = private_key

        elif isinstance(bag_value, SafeContents):
            parse_safe_contents(bag_value, certs, private_keys, password, load_private_key)

        else:
            # We don't care about CRL bags or secret bags
            pass
