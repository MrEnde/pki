from asn1crypto.cms import EncryptedData, KeyTransRecipientInfo, EnvelopedData
from asn1crypto.core import OctetString
from asn1crypto.keys import EncryptedPrivateKeyInfo
from asn1crypto.pkcs12 import Pfx, SafeContents, SafeBag
from asn1crypto.cms import KEKRecipientInfo

from pkcs12.types import ExtendEncryptionAlgorithm
from pygost.gost28147 import cfb_decrypt

from pygost.gost34112012512 import pbkdf2, pbkdf2_base
from pygost.gost341194 import GOST341194

from privatekey import ExtendPrivateKeyInfo
from pygost.wrap import unwrap_cryptopro

with open("main_test_container.pfx", "rb") as file:
    data = file.read()

password = "12345678"

pfx = Pfx.load(data)
authenticated_safe = pfx.authenticated_safe

for content_info in authenticated_safe:
    content = content_info['content']
    # if isinstance(content, EncryptedData):
    #     print(content.native)

    if isinstance(content, OctetString):
        safe_contents = SafeContents.load(content.native)
        pkcs8_shrouded_key_bag: SafeBag = safe_contents[0]
        encrypted_private_key_info: EncryptedPrivateKeyInfo = pkcs8_shrouded_key_bag["bag_value"]

        print(pkcs8_shrouded_key_bag["bag_id"])

        encryption_algorithm = encrypted_private_key_info["encryption_algorithm"]
        print(encryption_algorithm.native)
        pbes1_params = encryption_algorithm["parameters"]
        print(pbes1_params.native)
        # salt = pbes1_params["salt"].native

        # private_key = cfb_decrypt(
        #     key,
        #     bytes(encrypted_private_key_info["encrypted_data"]),
        #     sbox="id-tc26-gost-28147-param-Z",
        #     iv=bytes.fromhex(pbes1_params["salt"].native.hex()[:16])
        # )
        # print(KeyTransRecipientInfo.load(private_key))
        # print(pbes2_params.native)
        # print(pkcs8_shrouded_key_bag.native)
        # print(private_key)
        # print(ExtendPrivateKeyInfo.load(private_key))
        # print(safe_contents["encryptionAlgorithm"]["parameters"])


# pfx, tail = PFX().decode(self.pfx_raw)
# self.assertSequenceEqual(tail, b"")
# _, outer_safe_contents = pfx["authSafe"]["content"].defined
# safe_contents, tail = OctetStringSafeContents().decode(
#     bytes(outer_safe_contents[0]["bagValue"]),
# )
# self.assertSequenceEqual(tail, b"")
# safe_bag = safe_contents[0]
# shrouded_key_bag, tail = PKCS8ShroudedKeyBag().decode(
#     bytes(safe_bag["bagValue"]),
# )
# self.assertSequenceEqual(tail, b"")
# _, pbes2_params = shrouded_key_bag["encryptionAlgorithm"]["parameters"].defined
# _, pbkdf2_params = pbes2_params["keyDerivationFunc"]["parameters"].defined
# _, enc_scheme_params = pbes2_params["encryptionScheme"]["parameters"].defined
#
# key = gost34112012_pbkdf2(
#     password=self.password.encode("utf-8"),
#     salt=bytes(pbkdf2_params["salt"]["specified"]),
#     iterations=int(pbkdf2_params["iterationCount"]),
#     dklen=32,
# )
# cfb_decrypt(
#     key,
#     bytes(shrouded_key_bag["encryptedData"]),
#     iv=bytes(enc_scheme_params["iv"]),
#     sbox="id-tc26-gost-28147-param-Z",
# )