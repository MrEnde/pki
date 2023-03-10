from typing import Any

from gostcrypto.gostoid import ObjectIdentifier
from gostcrypto.gostsignature import MODE_256, MODE_512
from gostcrypto.utils import check_value, bytearray_to_int

from pygost.gost3410 import (
    pub_unmarshal,
    public_key,
    pub_marshal,
    verify,
    sign,
    GOST3410Curve,
    CURVES,
    prv_unmarshal,
)

CURVES_R_1323565_1_024_2019: dict = CURVES


def new(mode: int, curve: GOST3410Curve) -> 'GOST34102012':
    """
    Create a new signature object and returns it.

    Args:
        mode: Signature generation or verification mode.
        curve: Parameters of the elliptic curve.

    Returns:
        New signature object.

    Raises:
        GOSTSignatureError('GOSTSignatureError: unsupported signature mode'): In
          case of unsupported signature mode.
        GOSTSignatureError('GOSTSignatureError: invalid parameters of the
          elliptic curve'): If the elliptic curve parameters are incorrect.
    """
    if mode not in (MODE_256, MODE_512):
        raise GOSTSignatureError('GOSTSignatureError: unsupported signature mode')
    return GOST34102012(mode, curve)


class GOST34102012:
    """
    Class that implements digital signature function.

    Methods:
        sign(): Creating a signature.
        verify(): Signature verification.
        public_key_generate(): Generating a public key.

    Attributes:
        oid: String  with the dotted representation of the object identifier
          respective to the signature generation or verification mode.
        oid.name: String  with name of the object identifier respective to the
          the signature generation or verification mode.
        oid.digit: The object identifier respective the signature generation or
          verification mode as a tuple of integers.
        oid.octet: The object identifier respective the signature generation or
          verification mode as a byte object encoded ASN.1.
    """

    # pylint: disable=too-many-instance-attributes
    def __init__(self, mode: int, curve: GOST3410Curve) -> None:
        """
        Initialize the signature object.

        Args:
            mode: Signature generation or verification mode.
            curve: Parameters of the elliptic curve.
        """
        self._set_size(mode)
        if mode == MODE_256:
            self.oid = ObjectIdentifier('1.2.643.7.1.1.1.1')
        else:
            self.oid = ObjectIdentifier('1.2.643.7.1.1.1.2')
        self.curve = curve

    def _set_size(self, mode: int) -> None:
        if mode == MODE_256:
            self._size = 32
        else:
            self._size = 64

    def sign(self, private_key: bytearray, digest: bytearray,
             rand_k: bytearray = None) -> bytearray:
        """
        Create a signature.

        Args:
            private_key: Private signature key (as a byte object).
            digest: Digest for which the signature is calculated.  This value
              must be obtained using the 'streebog' algorithm in accordance with
              GOST 34.11-2012.
            rand_k: Random (pseudo-random) number (as a byte object). By
              default, it is generated by the function itself.

        Returns:
            Signature for provided digest (as a byte object).

        Raises:
            GOSTSignatureError('GOSTSignatureError: invalid private key value'):
              If the private key value is incorrect.
            GOSTSignatureError('GOSTSignatureError: invalid digest value'): If
              the digest value is incorrect.
            GOSTSignatureError('GOSTSignatureError: invalid random value'): If
              the random value is incorrect.
        """
        if not check_value(private_key, self._size):
            raise GOSTSignatureError('GOSTSignatureError: invalid private key value')
        if not check_value(digest, self._size):
            raise GOSTSignatureError('GOSTSignatureError: invalid digest value')

        prv_key = prv_unmarshal(private_key)

        return sign(
            curve=self.curve,
            digest=digest,
            rand=rand_k,
            prv=prv_key
        )

    def verify(self, public_key: Any, digest: bytearray | bytes,
               signature: bytearray | bytes) -> bool:
        """
        Verify a signature.

        Args:
            public_key: Public signature key (as a byte object).
            digest: Digest for which to be checked signature (as a byte object).
            signature: Signature of the digest being checked (as a byte object).

        Returns:
            The result of the signature verification ('True' or 'False').

        Raises:
            GOSTSignatureError('GOSTSignatureError: invalid public key value'):
              If the public key value is incorrect.
            GOSTSignatureError('GOSTSignatureError: invalid signature value'):
              If the signature value is incorrect.
            GOSTSignatureError('GOSTSignatureError: invalid digest value'): If
              the digest value is incorrect.
        """
        if not check_value(public_key, self._size * 2):
            raise GOSTSignatureError('GOSTSignatureError: invalid public key value')
        if not check_value(signature, self._size * 2):
            raise GOSTSignatureError('GOSTSignatureError: invalid signature value')
        if not check_value(digest, self._size):
            raise GOSTSignatureError('GOSTSignatureError: invalid digest value')

        pub_key = pub_unmarshal(public_key)

        return verify(
            curve=self.curve,
            pub=pub_key,
            digest=digest,
            signature=signature
        )

    def public_key_generate(self, private_key: Any) -> bytes:
        """
        Generate a public key.

        Args:
            private_key: Private signature key (as a byte object).

        Returns:
            Public key (as a byte object).

        Raises:
            GOSTSignatureError('GOSTSignatureError: invalid private key'): If
              the private key value is incorrect.
        """
        if not check_value(private_key, self._size):
            raise GOSTSignatureError('GOSTSignatureError: invalid private key')

        prv = prv_unmarshal(private_key)

        return pub_marshal(
            public_key(curve=self.curve, prv=prv)
        )


class GOSTSignatureError(Exception):
    """
    The exception class.

    This is a class that implements exceptions that can occur when input data
    is incorrect.
    """
