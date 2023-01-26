from asn1crypto.x509 import Certificate
from asn1crypto.pem import unarmor

from gostcrypto.gostsignature import gost_34_10_2012, MODE_512, MODE_256
from gostcrypto.gosthash import gost_34_11_2012
from pki.params_sets import CURVES_R_1323565_1_024_2019

with open("cert.pem", "rb") as file:
    object_name, headers, der_bytes = unarmor(file.read())


cert = Certificate.load(der_bytes)
print(cert.native)
cert_signature = cert['signature_value'].native
tbs = cert['tbs_certificate'].dump()

public_key_info = cert.public_key
public_key = public_key_info['public_key'].native
public_key_params = public_key_info.curve
param_set = public_key_params['public_key_param_set'].native

digest = gost_34_11_2012.new('streebog256', data=tbs).digest()

signer = gost_34_10_2012.new(MODE_256, CURVES_R_1323565_1_024_2019[param_set])

print(signer.verify(
    public_key=public_key,
    digest=digest,
    signature=cert_signature
))
