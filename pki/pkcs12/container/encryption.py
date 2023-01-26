import asn1
from asn1crypto.core import Integer, OctetString, ObjectIdentifier, ParsableOctetString
from pyderasn import DecodePathDefBy

from pkcs12.types import Blob, ExportBlob, PrivateKeyOID
from pygost.asn1schemas.cms import ContentInfo
from pygost.asn1schemas.oids import id_envelopedData, id_tc26_gost3410_2012_512, id_tc26_gost3410_2012_256
from pygost.gost28147 import cfb_decrypt, DEFAULT_SBOX, ecb_decrypt
from pygost.gost3410 import CURVES, prv_unmarshal, pub_unmarshal
from pygost.gost3410_vko import kek_34102012256, ukm_unmarshal

from pygost.gost341194 import GOST341194
from pygost.kdf import kdf_gostr3411_2012_256

from privatekey import ExtendPrivateKeyInfo, PrivateKeyAlgorithm, PrivateKeyAlgorithmId, Gost3410Parameters, \
    GostKeyAlgorithmId, GostSignedDigestAlgorithmId
from pygost.wrap import unwrap_cryptopro
from schemas import CPExportBlob2


def unwrap_gost(kek, data, sbox=DEFAULT_SBOX):
    if len(data) != 44:
        raise ValueError("Invalid data length")
    ukm, cek_enc, cek_mac = data[:8], data[8:8 + 32], data[-4:]
    cek = ecb_decrypt(kek, cek_enc, sbox=sbox)
    return cek


def build_private_key(key, oids, algorithm):
    private_key = ParsableOctetString(key)
    algorithm_id = PrivateKeyAlgorithmId(algorithm)
    parameters = GostKeyAlgorithmId(oids[0])
    digest = GostSignedDigestAlgorithmId(oids[1])

    oids = Gost3410Parameters()
    oids["public_key_param_set"] = parameters
    oids["digest_param_set"] = digest

    private_key_algorithm = PrivateKeyAlgorithm()
    private_key_algorithm["algorithm"] = algorithm_id
    private_key_algorithm["parameters"] = oids

    builder = ExtendPrivateKeyInfo()
    builder["version"] = Integer(0)
    builder["private_key_algorithm"] = private_key_algorithm
    builder["private_key"] = private_key

    return builder.dump()


def get_oids(string):
    decoder = asn1.Decoder()
    decoder.start(string)
    tag, value = decoder.read()
    decoder.start(value)
    tag, value = decoder.read()
    tag, value = decoder.read()
    decoder.start(value)
    tag, value = decoder.read()
    tag, value = decoder.read()
    decoder.start(value)
    tag, value = decoder.read()
    params = value
    tag, value = decoder.read()
    dgst = value
    return params, dgst


def oid_algorithm(algorithm_type: str) -> str:
    if algorithm_type == "42aa":
        return "1.2.643.7.1.1.1.2"
    return "1.2.643.7.1.1.1.1"


def extract_private_key(container, encrypted_content, password: bytes):
    print(container)

    parameters = container["parameters"]

    salt = parameters["salt"].native
    iterations = parameters["iterations"].native

    password = password.decode("utf-8").encode("utf-16le")
    encrypted_key = password
    count = 1
    while count < iterations + 1:
        hex_view = bytes.fromhex(encrypted_key.hex() + salt.hex() + str(hex(count))[2:].zfill(4))
        encrypted_key = GOST341194(hex_view).digest()
        count += 1

    first_step = cfb_decrypt(encrypted_key, encrypted_content, iv=bytes.fromhex(salt.hex()[:16]))

    blob = Blob.load(first_step)

    blob_value = bytes.fromhex(blob["value"].native.hex()[32:])

    algorithm_type = blob["value"].native.hex()[:32][8:12]

    exporter_blob = ExportBlob.load(blob_value)

    oids = bytes(CPExportBlob2().decode(exporter_blob["value"].dump())[0]["oids"])

    ukm = exporter_blob["value"]["ukm"].native.hex()

    content_encryption_key_enc = exporter_blob["value"]["cek"]["enc"].native.hex()
    content_encryption_key_mac = exporter_blob["value"]["cek"]["mac"].native.hex()

    key_encryption_key = kdf_gostr3411_2012_256(encrypted_key, bytes.fromhex("26bdb878"), bytes.fromhex(ukm))

    if algorithm_type == "46aa":
        private_key = unwrap_gost(
            key_encryption_key,
            bytes.fromhex(ukm + content_encryption_key_enc + content_encryption_key_mac)
        )
    elif algorithm_type == "42aa":
        cek_enc2 = [content_encryption_key_enc[i:i + 64] for i in range(0, len(content_encryption_key_enc), 64)]
        buffer = []
        for i in cek_enc2:
            buffer.append(unwrap_gost(key_encryption_key, bytes.fromhex(ukm + i + content_encryption_key_mac)).hex())
        private_key = bytes.fromhex("".join(buffer))
    else:
        raise ValueError()

    oids = get_oids(oids)

    return build_private_key(private_key, oids, oid_algorithm(algorithm_type))


def keker(curve, prv, pub, ukm):
    return kek_34102012256(
        curve,
        prv_unmarshal(prv),
        pub_unmarshal(pub),
        ukm_unmarshal(ukm),
    )

def process_cms(
    content_info_raw,
    prv_key_our,
    curve_name,
    keker
):
    sbox = "id-tc26-gost-28147-param-Z"
    content_info, tail = ContentInfo().decode(content_info_raw, ctx={
        "defines_by_path": [
            (
                (
                    "content",
                    DecodePathDefBy(id_envelopedData),
                    "recipientInfos",
                    any,
                    "ktri",
                    "encryptedKey",
                    DecodePathDefBy(spki_algorithm),
                    "transportParameters",
                    "ephemeralPublicKey",
                    "algorithm",
                    "algorithm",
                ),
                (
                    (
                        ("..", "subjectPublicKey"),
                        {
                            id_tc26_gost3410_2012_256: OctetString(),
                            id_tc26_gost3410_2012_512: OctetString(),
                        },
                    ),
                ),
            ) for spki_algorithm in (
                id_tc26_gost3410_2012_256,
                id_tc26_gost3410_2012_512,
            )
        ],
    })

    _, enveloped_data = content_info["content"].defined
    eci = enveloped_data["encryptedContentInfo"]
    ri = enveloped_data["recipientInfos"][0]

    _, encrypted_key = ri["ktri"]["encryptedKey"].defined
    ukm = bytes(encrypted_key["transportParameters"]["ukm"])
    spk = encrypted_key["transportParameters"]["ephemeralPublicKey"]["subjectPublicKey"]

    _, pub_key_their = spk.defined
    curve = CURVES[curve_name]
    kek = keker(curve, prv_key_our, bytes(pub_key_their), ukm)
    key_wrapped = bytes(encrypted_key["sessionEncryptedKey"]["encryptedKey"])
    mac = bytes(encrypted_key["sessionEncryptedKey"]["macKey"])
    cek = unwrap_cryptopro(kek, ukm + key_wrapped + mac, sbox=sbox)
    ciphertext = bytes(eci["encryptedContent"])

    _, encryption_params = eci["contentEncryptionAlgorithm"]["parameters"].defined
    iv = bytes(encryption_params["iv"])

    return cfb_decrypt(cek, ciphertext, iv, sbox=sbox, mesh=True)