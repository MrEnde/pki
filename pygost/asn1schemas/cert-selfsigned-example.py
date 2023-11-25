#!/usr/bin/env python3
"""Create example self-signed X.509 certificate
"""

from argparse import ArgumentParser
from base64 import standard_b64decode
from base64 import standard_b64encode
from datetime import datetime
from datetime import timedelta
from os import urandom
from sys import exit as sys_exit
from sys import stdout
from textwrap import fill

from pyderasn import Any
from pyderasn import BitString
from pyderasn import Boolean
from pyderasn import IA5String
from pyderasn import Integer
from pyderasn import OctetString
from pyderasn import PrintableString
from pyderasn import UTCTime

from pygost.asn1schemas.oids import id_at_commonName
from pygost.asn1schemas.oids import id_at_countryName
from pygost.asn1schemas.oids import id_ce_authorityKeyIdentifier
from pygost.asn1schemas.oids import id_ce_basicConstraints
from pygost.asn1schemas.oids import id_ce_keyUsage
from pygost.asn1schemas.oids import id_ce_subjectAltName
from pygost.asn1schemas.oids import id_ce_subjectKeyIdentifier
from pygost.asn1schemas.oids import id_tc26_gost3410_2012_256
from pygost.asn1schemas.oids import id_tc26_gost3410_2012_256_paramSetA
from pygost.asn1schemas.oids import id_tc26_gost3410_2012_256_paramSetB
from pygost.asn1schemas.oids import id_tc26_gost3410_2012_256_paramSetC
from pygost.asn1schemas.oids import id_tc26_gost3410_2012_256_paramSetD
from pygost.asn1schemas.oids import id_tc26_gost3410_2012_512
from pygost.asn1schemas.oids import id_tc26_gost3410_2012_512_paramSetA
from pygost.asn1schemas.oids import id_tc26_gost3410_2012_512_paramSetB
from pygost.asn1schemas.oids import id_tc26_gost3410_2012_512_paramSetC
from pygost.asn1schemas.oids import id_tc26_signwithdigest_gost3410_2012_256
from pygost.asn1schemas.oids import id_tc26_signwithdigest_gost3410_2012_512
from pygost.asn1schemas.prvkey import PrivateKey
from pygost.asn1schemas.prvkey import PrivateKeyAlgorithmIdentifier
from pygost.asn1schemas.prvkey import PrivateKeyInfo
from pygost.asn1schemas.x509 import AlgorithmIdentifier
from pygost.asn1schemas.x509 import AttributeType
from pygost.asn1schemas.x509 import AttributeTypeAndValue
from pygost.asn1schemas.x509 import AttributeValue
from pygost.asn1schemas.x509 import AuthorityKeyIdentifier
from pygost.asn1schemas.x509 import BasicConstraints
from pygost.asn1schemas.x509 import Certificate
from pygost.asn1schemas.x509 import CertificateSerialNumber
from pygost.asn1schemas.x509 import Extension
from pygost.asn1schemas.x509 import Extensions
from pygost.asn1schemas.x509 import GeneralName
from pygost.asn1schemas.x509 import GostR34102012PublicKeyParameters
from pygost.asn1schemas.x509 import KeyIdentifier
from pygost.asn1schemas.x509 import KeyUsage
from pygost.asn1schemas.x509 import Name
from pygost.asn1schemas.x509 import RDNSequence
from pygost.asn1schemas.x509 import RelativeDistinguishedName
from pygost.asn1schemas.x509 import SubjectAltName
from pygost.asn1schemas.x509 import SubjectKeyIdentifier
from pygost.asn1schemas.x509 import SubjectPublicKeyInfo
from pygost.asn1schemas.x509 import TBSCertificate
from pygost.asn1schemas.x509 import Time
from pygost.asn1schemas.x509 import Validity
from pygost.asn1schemas.x509 import Version
from pygost.gost3410 import CURVES
from pygost.gost3410 import prv_unmarshal
from pygost.gost3410 import pub_marshal
from pygost.gost3410 import public_key
from pygost.gost3410 import sign
from pygost.gost34112012256 import GOST34112012256
from pygost.gost34112012512 import GOST34112012512
from pygost.utils import bytes2long

parser = ArgumentParser(description="Self-signed X.509 certificate creator")
parser.add_argument(
    "--ca",
    action="store_true",
    help="Enable BasicConstraints.cA",
)
parser.add_argument(
    "--cn",
    required=True,
    help="Subject's CommonName",
)
parser.add_argument(
    "--country",
    help="Subject's Country",
)
parser.add_argument(
    "--serial",
    help="Serial number",
)
parser.add_argument(
    "--ai",
    required=True,
    help="Signing algorithm: {256[ABCD],512[ABC]}",
)
parser.add_argument(
    "--issue-with",
    help="Path to PEM with CA to issue the child",
)
parser.add_argument(
    "--reuse-key",
    help="Path to PEM with the key to reuse",
)
parser.add_argument(
    "--out-key",
    help="Path to PEM with the resulting key",
)
parser.add_argument(
    "--only-key",
    action="store_true",
    help="Only generate the key",
)
parser.add_argument(
    "--out-cert",
    help="Path to PEM with the resulting certificate",
)
args = parser.parse_args()
AIs = {
    "256A": {
        "publicKeyParamSet": id_tc26_gost3410_2012_256_paramSetA,
        "key_algorithm": id_tc26_gost3410_2012_256,
        "prv_len": 32,
        "curve": CURVES["id-tc26-gost-3410-2012-256-paramSetA"],
        "sign_algorithm": id_tc26_signwithdigest_gost3410_2012_256,
        "hasher": GOST34112012256,
    },
    "256B": {
        "publicKeyParamSet": id_tc26_gost3410_2012_256_paramSetB,
        "key_algorithm": id_tc26_gost3410_2012_256,
        "prv_len": 32,
        "curve": CURVES["id-tc26-gost-3410-2012-256-paramSetB"],
        "sign_algorithm": id_tc26_signwithdigest_gost3410_2012_256,
        "hasher": GOST34112012256,
    },
    "256C": {
        "publicKeyParamSet": id_tc26_gost3410_2012_256_paramSetC,
        "key_algorithm": id_tc26_gost3410_2012_256,
        "prv_len": 32,
        "curve": CURVES["id-tc26-gost-3410-2012-256-paramSetC"],
        "sign_algorithm": id_tc26_signwithdigest_gost3410_2012_256,
        "hasher": GOST34112012256,
    },
    "256D": {
        "publicKeyParamSet": id_tc26_gost3410_2012_256_paramSetD,
        "key_algorithm": id_tc26_gost3410_2012_256,
        "prv_len": 32,
        "curve": CURVES["id-tc26-gost-3410-2012-256-paramSetD"],
        "sign_algorithm": id_tc26_signwithdigest_gost3410_2012_256,
        "hasher": GOST34112012256,
    },
    "512A": {
        "publicKeyParamSet": id_tc26_gost3410_2012_512_paramSetA,
        "key_algorithm": id_tc26_gost3410_2012_512,
        "prv_len": 64,
        "curve": CURVES["id-tc26-gost-3410-12-512-paramSetA"],
        "sign_algorithm": id_tc26_signwithdigest_gost3410_2012_512,
        "hasher": GOST34112012512,
    },
    "512B": {
        "publicKeyParamSet": id_tc26_gost3410_2012_512_paramSetB,
        "key_algorithm": id_tc26_gost3410_2012_512,
        "prv_len": 64,
        "curve": CURVES["id-tc26-gost-3410-12-512-paramSetB"],
        "sign_algorithm": id_tc26_signwithdigest_gost3410_2012_512,
        "hasher": GOST34112012512,
    },
    "512C": {
        "publicKeyParamSet": id_tc26_gost3410_2012_512_paramSetC,
        "key_algorithm": id_tc26_gost3410_2012_512,
        "prv_len": 64,
        "curve": CURVES["id-tc26-gost-3410-2012-512-paramSetC"],
        "sign_algorithm": id_tc26_signwithdigest_gost3410_2012_512,
        "hasher": GOST34112012512,
    },
}
ai = AIs[args.ai]

ca_prv = None
ca_cert = None
ca_subj = None
ca_ai = None
if args.issue_with is not None:
    with open(args.issue_with, "rb") as fd:
        lines = fd.read().decode("ascii").split("-----")
    idx = lines.index("BEGIN PRIVATE KEY")
    if idx == -1:
        raise ValueError("PEM has no PRIVATE KEY")
    prv_raw = standard_b64decode(lines[idx + 1])
    idx = lines.index("BEGIN CERTIFICATE")
    if idx == -1:
        raise ValueError("PEM has no CERTIFICATE")
    cert_raw = standard_b64decode(lines[idx + 1])
    pki = PrivateKeyInfo().decod(prv_raw)
    ca_prv = prv_unmarshal(bytes(OctetString().decod(bytes(pki["privateKey"]))))
    ca_cert = Certificate().decod(cert_raw)
    tbs = ca_cert["tbsCertificate"]
    ca_subj = tbs["subject"]
    curve_oid = GostR34102012PublicKeyParameters().decod(bytes(
        tbs["subjectPublicKeyInfo"]["algorithm"]["parameters"]
    ))["publicKeyParamSet"]
    ca_ai = next(iter([
        params for params in AIs.values()
        if params["publicKeyParamSet"] == curve_oid
    ]))

key_params = GostR34102012PublicKeyParameters((
    ("publicKeyParamSet", ai["publicKeyParamSet"]),
))


def pem(obj):
    return fill(standard_b64encode(obj.encode()).decode("ascii"), 64)


if args.reuse_key is not None:
    with open(args.reuse_key, "rb") as fd:
        lines = fd.read().decode("ascii").split("-----")
    idx = lines.index("BEGIN PRIVATE KEY")
    if idx == -1:
        raise ValueError("PEM has no PRIVATE KEY")
    prv_raw = standard_b64decode(lines[idx + 1])
    pki = PrivateKeyInfo().decod(prv_raw)
    prv = prv_unmarshal(bytes(OctetString().decod(bytes(pki["privateKey"]))))
else:
    prv_raw = urandom(ai["prv_len"])
    out = stdout if args.out_key is None else open(args.out_key, "w")
    print("-----BEGIN PRIVATE KEY-----", file=out)
    print(pem(PrivateKeyInfo((
        ("version", Integer(0)),
        ("privateKeyAlgorithm", PrivateKeyAlgorithmIdentifier((
            ("algorithm", ai["key_algorithm"]),
            ("parameters", Any(key_params)),
        ))),
        ("privateKey", PrivateKey(OctetString(prv_raw).encode())),
    ))), file=out)
    print("-----END PRIVATE KEY-----", file=out)
    if args.only_key:
        sys_exit()
    prv = prv_unmarshal(prv_raw)

curve = ai["curve"]
pub_raw = pub_marshal(public_key(curve, prv))
rdn = [RelativeDistinguishedName((
    AttributeTypeAndValue((
        ("type", AttributeType(id_at_commonName)),
        ("value", AttributeValue(PrintableString(args.cn))),
    )),
))]
if args.country:
    rdn.append(RelativeDistinguishedName((
        AttributeTypeAndValue((
            ("type", AttributeType(id_at_countryName)),
            ("value", AttributeValue(PrintableString(args.country))),
        )),
    )))
subj = Name(("rdnSequence", RDNSequence(rdn)))
not_before = datetime.utcnow()
not_after = not_before + timedelta(days=365 * (10 if args.ca else 1))
ai_sign = AlgorithmIdentifier((
    ("algorithm", (ai if ca_ai is None else ca_ai)["sign_algorithm"]),
))
exts = [
    Extension((
        ("extnID", id_ce_subjectKeyIdentifier),
        ("extnValue", OctetString(
            SubjectKeyIdentifier(GOST34112012256(pub_raw).digest()[:20]).encode()
        )),
    )),
    Extension((
        ("extnID", id_ce_keyUsage),
        ("critical", Boolean(True)),
        ("extnValue", OctetString(KeyUsage(
            ("keyCertSign" if args.ca else "digitalSignature",),
        ).encode())),
    )),
]
if args.ca:
    exts.append(Extension((
        ("extnID", id_ce_basicConstraints),
        ("critical", Boolean(True)),
        ("extnValue", OctetString(BasicConstraints((
            ("cA", Boolean(True)),
        )).encode())),
    )))
else:
    exts.append(Extension((
        ("extnID", id_ce_subjectAltName),
        ("extnValue", OctetString(
            SubjectAltName((
                GeneralName(("dNSName", IA5String(args.cn))),
            )).encode()
        )),
    )))
if ca_ai is not None:
    caKeyId = [
        bytes(SubjectKeyIdentifier().decod(bytes(ext["extnValue"])))
        for ext in ca_cert["tbsCertificate"]["extensions"]
        if ext["extnID"] == id_ce_subjectKeyIdentifier
    ][0]
    exts.append(Extension((
        ("extnID", id_ce_authorityKeyIdentifier),
        ("extnValue", OctetString(AuthorityKeyIdentifier((
            ("keyIdentifier", KeyIdentifier(caKeyId)),
        )).encode())),
    )))

serial = (
    bytes2long(GOST34112012256(urandom(16)).digest()[:20])
    if args.serial is None else int(args.serial)
)
tbs = TBSCertificate((
    ("version", Version("v3")),
    ("serialNumber", CertificateSerialNumber(serial)),
    ("signature", ai_sign),
    ("issuer", subj if ca_ai is None else ca_subj),
    ("validity", Validity((
        ("notBefore", Time(("utcTime", UTCTime(not_before)))),
        ("notAfter", Time(("utcTime", UTCTime(not_after)))),
    ))),
    ("subject", subj),
    ("subjectPublicKeyInfo", SubjectPublicKeyInfo((
        ("algorithm", AlgorithmIdentifier((
            ("algorithm", ai["key_algorithm"]),
            ("parameters", Any(key_params)),
        ))),
        ("subjectPublicKey", BitString(OctetString(pub_raw).encode())),
    ))),
    ("extensions", Extensions(exts)),
))
cert = Certificate((
    ("tbsCertificate", tbs),
    ("signatureAlgorithm", ai_sign),
    ("signatureValue", BitString(
        sign(curve, prv, ai["hasher"](tbs.encode()).digest()[::-1])
        if ca_ai is None else
        sign(ca_ai["curve"], ca_prv, ca_ai["hasher"](tbs.encode()).digest()[::-1])
    )),
))
out = stdout if args.out_cert is None else open(args.out_cert, "w")
print("-----BEGIN CERTIFICATE-----", file=out)
print(pem(cert), file=out)
print("-----END CERTIFICATE-----", file=out)
