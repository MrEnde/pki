from pyderasn import Sequence, OctetString, ObjectIdentifier, Any, Integer


class CPParamsValue(Sequence):
    schema = (
        ("salt", OctetString()),
        ("iterations", Integer())
    )


class CPParams(Sequence):
    schema = (
        ("algorithm", ObjectIdentifier()),
        ("parameters", CPParamsValue())
    )


class KeyBagValue(Sequence):
    schema = (
        ("bagParams", CPParams()),
        ("bagValue", OctetString())
    )


class Blob(Sequence):
    schema = (
        ("version", Integer()),
        ("notused", Any()),
        ("value", OctetString())
    )


class ExportBlobCek(Sequence):
    schema = (
        ("enc", OctetString()),
        ("mac", OctetString())
    )


class InnerExportBlob(Sequence):
    schema = (
        ("ukm", OctetString()),
        ("cek", ExportBlobCek()),
        ("oids", Any())
    )


class CPExportBlob(Sequence):
    schema = (
        ("value", InnerExportBlob()),
        ("notused", OctetString())
    )


class PKeyOIDs(Sequence):
    schema = (
        ("parameters", ObjectIdentifier()),
        ("digest", ObjectIdentifier())
    )


class PrivateKeyParameters(Sequence):
    schema = (
        ("pub_algorithm", ObjectIdentifier()),
        ("parameters", PKeyOIDs())
    )


class PrivateKey(Sequence):
    schema = (
        ("version", Integer(0)),
        ("parameters", PrivateKeyParameters()),
        ("private_key", OctetString())
    )
