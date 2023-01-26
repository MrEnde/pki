#!/usr/bin/env python3
"""DANE's SPKI hash calculator
"""

from base64 import standard_b64decode
from hashlib import sha256
import sys

from pygost.asn1schemas.x509 import Certificate


lines = sys.stdin.read().split("-----")
idx = lines.index("BEGIN CERTIFICATE")
if idx == -1:
    raise ValueError("PEM has no CERTIFICATE")
cert_raw = standard_b64decode(lines[idx + 1])
cert = Certificate().decod(cert_raw)
print(sha256(cert["tbsCertificate"]["subjectPublicKeyInfo"].encode()).hexdigest())
