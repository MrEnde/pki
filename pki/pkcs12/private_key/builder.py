from asn1crypto.core import OctetString, ObjectIdentifier, Integer

from pkcs12.types import PrivateKeyOID
from privatekey import PrivateKeyAlgorithmId, PrivateKeyAlgorithm, ExtendPrivateKeyInfo


def build(key, oids, algorithm) -> bytes:
    private_key = OctetString(key)
    algorithm_id = PrivateKeyAlgorithmId(algorithm)
    parameters = ObjectIdentifier(oids[0])
    digest = ObjectIdentifier(oids[1])

    oids = PrivateKeyOID()
    oids["parameters"] = parameters
    oids["digest"] = digest

    private_key_algorithm = PrivateKeyAlgorithm()
    private_key_algorithm["algorithm"] = algorithm_id
    private_key_algorithm["parameters"] = oids

    builder = ExtendPrivateKeyInfo()
    builder["version"] = Integer(0)
    builder["private_key_algorithm"] = private_key_algorithm
    builder["private_key"] = private_key

    return builder.dump()