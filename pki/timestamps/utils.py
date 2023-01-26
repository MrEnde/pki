from cryptography.hazmat.primitives import hashes
from pyhanko.sign.general import get_pyca_cryptography_hash

from pki.pdf.general import get_cryptography_hash
from gostcrypto import gosthash


def dummy_digest(md_algorithm: str) -> bytes:
    md_spec = get_cryptography_hash(md_algorithm)
    digest = gosthash.new(md_spec).digest()
    return bytes(digest[::-1])
