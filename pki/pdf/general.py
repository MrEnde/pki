from pyhanko.sign import general
from gostcrypto import gostsignature

signature_modes = {
    'id-tc26-gost3410-12-256': gostsignature.MODE_256,
    'id-tc26-gost3410-12-512': gostsignature.MODE_512,
    'id-tc26-signwithdigest-gost3410-12-256': gostsignature.MODE_256,
    'id-tc26-signwithdigest-gost3410-12-512': gostsignature.MODE_512
}

oid_to_hash = {
    'id-tc26-gost3411-12-256': 'streebog256',
    'id-tc26-gost3411-12-512': 'streebog512',
    '1.2.643.7.1.1.2.3': 'streebog512',
    '1.2.643.7.1.1.2.2': 'streebog256'
}


def get_cryptography_hash(hash_algorithm: str):
    if hash_algorithm in oid_to_hash:
        return oid_to_hash[hash_algorithm]
    raise general.SigningError(f"{hash_algorithm}")


def get_signature_mode(signature_algorithm: str):
    if signature_algorithm in signature_modes:
        return signature_modes[signature_algorithm]

    raise general.SigningError(f"{signature_algorithm}")


def restore_oid_hash(name: str):
    if name == "streebog256":
        return "1.2.643.7.1.1.3.2"
    elif name == "streebog512":
        return "1.2.643.7.1.1.3.3"
    raise SigningError("")
