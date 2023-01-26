# coding: utf-8
# PyGOST -- Pure Python GOST cryptographic functions library
# Copyright (C) 2015-2022 Sergey Matveev <stargrave@stargrave.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
""":rfc:`5280` related structures (**NOT COMPLETE**)

They are taken from `PyDERASN <http://www.pyderasn.cypherpunks.ru/`__ tests.
"""

from pyderasn import Any
from pyderasn import BitString
from pyderasn import Boolean
from pyderasn import Choice
from pyderasn import GeneralizedTime
from pyderasn import IA5String
from pyderasn import Integer
from pyderasn import ObjectIdentifier
from pyderasn import OctetString
from pyderasn import PrintableString
from pyderasn import Sequence
from pyderasn import SequenceOf
from pyderasn import SetOf
from pyderasn import tag_ctxc
from pyderasn import tag_ctxp
from pyderasn import TeletexString
from pyderasn import UTCTime

from pygost.asn1schemas.oids import id_at_commonName
from pygost.asn1schemas.oids import id_at_countryName
from pygost.asn1schemas.oids import id_at_localityName
from pygost.asn1schemas.oids import id_at_organizationName
from pygost.asn1schemas.oids import id_at_stateOrProvinceName


class Version(Integer):
    schema = (
        ("v1", 0),
        ("v2", 1),
        ("v3", 2),
    )


class CertificateSerialNumber(Integer):
    pass


class AlgorithmIdentifier(Sequence):
    schema = (
        ("algorithm", ObjectIdentifier()),
        ("parameters", Any(optional=True)),
    )


class AttributeType(ObjectIdentifier):
    pass


class AttributeValue(Any):
    pass


class OrganizationName(Choice):
    schema = (
        ("printableString", PrintableString()),
        ("teletexString", TeletexString()),
    )


class AttributeTypeAndValue(Sequence):
    schema = (
        ("type", AttributeType(defines=(((".", "value"), {
            id_at_countryName: PrintableString(),
            id_at_stateOrProvinceName: PrintableString(),
            id_at_localityName: PrintableString(),
            id_at_organizationName: OrganizationName(),
            id_at_commonName: PrintableString(),
        }),))),
        ("value", AttributeValue()),
    )


class RelativeDistinguishedName(SetOf):
    schema = AttributeTypeAndValue()
    bounds = (1, float("+inf"))


class RDNSequence(SequenceOf):
    schema = RelativeDistinguishedName()


class Name(Choice):
    schema = (
        ("rdnSequence", RDNSequence()),
    )


class Time(Choice):
    schema = (
        ("utcTime", UTCTime()),
        ("generalTime", GeneralizedTime()),
    )


class Validity(Sequence):
    schema = (
        ("notBefore", Time()),
        ("notAfter", Time()),
    )


class GostR34102012PublicKeyParameters(Sequence):
    schema = (
        ("publicKeyParamSet", ObjectIdentifier()),
        ("digestParamSet", ObjectIdentifier(optional=True)),
    )


class SubjectPublicKeyInfo(Sequence):
    schema = (
        ("algorithm", AlgorithmIdentifier()),
        ("subjectPublicKey", BitString()),
    )


class UniqueIdentifier(BitString):
    pass


class KeyIdentifier(OctetString):
    pass


class SubjectKeyIdentifier(KeyIdentifier):
    pass


class BasicConstraints(Sequence):
    schema = (
        ("cA", Boolean(default=False)),
        # ("pathLenConstraint", PathLenConstraint(optional=True)),
    )


class Extension(Sequence):
    schema = (
        ("extnID", ObjectIdentifier()),
        ("critical", Boolean(default=False)),
        ("extnValue", OctetString()),
    )


class Extensions(SequenceOf):
    schema = Extension()
    bounds = (1, float("+inf"))


class TBSCertificate(Sequence):
    schema = (
        ("version", Version(expl=tag_ctxc(0), default="v1")),
        ("serialNumber", CertificateSerialNumber()),
        ("signature", AlgorithmIdentifier()),
        ("issuer", Name()),
        ("validity", Validity()),
        ("subject", Name()),
        ("subjectPublicKeyInfo", SubjectPublicKeyInfo()),
        ("issuerUniqueID", UniqueIdentifier(impl=tag_ctxp(1), optional=True)),
        ("subjectUniqueID", UniqueIdentifier(impl=tag_ctxp(2), optional=True)),
        ("extensions", Extensions(expl=tag_ctxc(3), optional=True)),
    )


class Certificate(Sequence):
    schema = (
        ("tbsCertificate", TBSCertificate()),
        ("signatureAlgorithm", AlgorithmIdentifier()),
        ("signatureValue", BitString()),
    )


class RevokedCertificates(SequenceOf):
    # schema = RevokedCertificate()
    schema = OctetString()  # dummy


class TBSCertList(Sequence):
    schema = (
        ("version", Version(optional=True)),
        ("signature", AlgorithmIdentifier()),
        ("issuer", Name()),
        ("thisUpdate", Time()),
        ("nextUpdate", Time(optional=True)),
        ("revokedCertificates", RevokedCertificates(optional=True)),
        ("crlExtensions", Extensions(expl=tag_ctxc(0), optional=True)),
    )


class CertificateList(Sequence):
    schema = (
        ("tbsCertList", TBSCertList()),
        ("signatureAlgorithm", AlgorithmIdentifier()),
        ("signatureValue", BitString()),
    )


class GeneralName(Choice):
    schema = (
        # ("otherName", AnotherName(impl=tag_ctxc(0))),
        # ("rfc822Name", IA5String(impl=tag_ctxp(1))),
        ("dNSName", IA5String(impl=tag_ctxp(2))),
        # ("x400Address", ORAddress(impl=tag_ctxp(3))),
        # ("x400Address", OctetString(impl=tag_ctxp(3))),
        # ("directoryName", Name(expl=tag_ctxc(4))),
        # ("ediPartyName", EDIPartyName(impl=tag_ctxc(5))),
        # ("uniformResourceIdentifier", IA5String(impl=tag_ctxp(6))),
        # ("iPAddress", OctetString(impl=tag_ctxp(7))),
        # ("registeredID", ObjectIdentifier(impl=tag_ctxp(8))),
    )


class GeneralNames(SequenceOf):
    schema = GeneralName()
    bounds = (1, float("+inf"))


class SubjectAltName(GeneralNames):
    pass


class AuthorityKeyIdentifier(Sequence):
    schema = (
        ("keyIdentifier", KeyIdentifier(impl=tag_ctxp(0), optional=True)),
        # ("authorityCertIssuer", GeneralNames(impl=tag_ctxc(1), optional=True)),
        # (
        #     "authorityCertSerialNumber",
        #     CertificateSerialNumber(impl=tag_ctxp(2), optional=True),
        # ),
    )


class KeyUsage(BitString):
    schema = (
        ("digitalSignature", 0),
        ("nonRepudiation", 1),
        ("keyEncipherment", 2),
        ("dataEncipherment", 3),
        ("keyAgreement", 4),
        ("keyCertSign", 5),
        ("cRLSign", 6),
        ("encipherOnly", 7),
        ("decipherOnly", 8),
    )
