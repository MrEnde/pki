from base64 import b64decode

from asn1crypto import pem
from asn1crypto.keys import (
    Attributes, _ForceNullParameters,
    PrivateKeyInfo
)
from asn1crypto.core import (
    ObjectIdentifier, Any, Sequence,
    Integer, ParsableOctetString, OctetString
)

from params_sets import CURVES_R_1323565_1_024_2019


class PrivateKeyAlgorithmId(ObjectIdentifier):
    """
    These OIDs for various public keys are reused when storing private keys
    inside of a PKCS#8 structure

    Original Name: None
    Source: https://tools.ietf.org/html/rfc3279
    """

    _map = {
        '1.2.643.7.1.1.1.2': 'id-tc26-gost3410-12-512',
        '1.2.643.7.1.1.1.1': 'id-tc26-gost3410-12-256',
    }


class GostKeyAlgorithmId(ObjectIdentifier):
    _map = {
        '1.2.643.7.1.1.1.1': 'id-tc26-gost3410-12-256',
        '1.2.643.7.1.1.1.2': 'id-tc26-gost3410-12-512',
        '1.2.643.7.1.1.3.2': 'id-tc26-signwithdigest-gost3410-12-256',
        '1.2.643.7.1.1.3.3': 'id-tc26-signwithdigest-gost3410-12-512',
        '1.2.643.7.1.2.1.1': 'id-tc26-gost-3410-12-256-constants',
        '1.2.643.7.1.2.1.1.1': 'id-tc26-gost-3410-12-256-paramSetA',
        '1.2.643.7.1.2.1.1.2': 'id-tc26-gost-3410-12-256-paramSetB',
        '1.2.643.7.1.2.1.1.3': 'id-tc26-gost-3410-12-256-paramSetC',
        '1.2.643.7.1.2.1.1.4': 'id-tc26-gost-3410-12-256-paramSetD',
        '1.2.643.7.1.2.1.2': 'id-tc26-gost-3410-12-512-constants',
        '1.2.643.7.1.2.1.2.0': 'id-tc26-gost-3410-12-512-paramSetTest',
        '1.2.643.7.1.2.1.2.1': 'id-tc26-gost-3410-12-512-paramSetA',
        '1.2.643.7.1.2.1.2.2': 'id-tc26-gost-3410-12-512-paramSetB',
        '1.2.643.7.1.2.1.2.3': 'id-tc26-gost-3410-12-512-paramSetС',
        '1.2.643.2.2.35.1': 'id-tc26-gost-3410-12-256-paramSetA'
    }


class GostSignedDigestAlgorithmId(ObjectIdentifier):
    _map = {
        '1.2.643.7.1.1.2.2': 'id-tc26-gost3411-12-256',
        '1.2.643.7.1.1.2.3': 'id-tc26-gost3411-12-512'
    }

    _reverse_map = {
        'id-tc26-gost3411-12-256': '1.2.643.7.1.1.2.2',
        'id-tc26-gost3411-12-512': '1.2.643.7.1.1.2.3'
    }


class Gost3410Parameters(Sequence):
    _fields = [
        ('public_key_param_set', GostKeyAlgorithmId),
        ('digest_param_set', GostSignedDigestAlgorithmId, {'optional': True})
    ]

    @property
    def key_curve(self):
        param_set = self['public_key_param_set'].native

        return CURVES_R_1323565_1_024_2019[param_set]


class PrivateKeyAlgorithm(_ForceNullParameters, Sequence):
    """
    Original Name: PrivateKeyAlgorithmIdentifier
    Source: https://tools.ietf.org/html/rfc5208#page-3
    """

    _fields = [
        ('algorithm', PrivateKeyAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]

    _oid_pair = ('algorithm', 'parameters')
    _oid_specs = {
        'id-tc26-gost3410-12-512': Gost3410Parameters,
        'id-tc26-gost3410-12-256': Gost3410Parameters
    }


class ExtendPrivateKeyInfo(PrivateKeyInfo):
    """
    Source: https://tools.ietf.org/html/rfc5208#page-3
    """

    _fields = [
        ('version', Integer),
        ('private_key_algorithm', PrivateKeyAlgorithm),
        ('private_key', ParsableOctetString),
        ('attributes', Attributes, {'implicit': 0, 'optional': True}),
    ]

    def _private_key_spec(self):
        algorithm = self['private_key_algorithm']['algorithm'].native
        return {
            'id-tc26-gost3410-12-512': OctetString,
            'id-tc26-gost3410-12-256': OctetString
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

        params = self['private_key_algorithm']['parameters']

        return params

    # _spec_callbacks = {
    #     'private_key': _private_key_spec
    # }
    _spec_callbacks = None