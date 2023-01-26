import re
import subprocess
import uuid

from asn1crypto.keys import PrivateKeyInfo
from asn1crypto.x509 import Certificate
from certomancer import registry, PKIArchitecture
from certomancer.config_utils import ConfigurationError
from certomancer.registry import CertomancerObjectNotFoundError, CertificateSpec
from fastapi import HTTPException, Body
from fastapi.responses import StreamingResponse
from fastapi_utils.inferring_router import InferringRouter

from certomancer.registry import CertLabel, ArchLabel
from pydantic import BaseModel
from pyhanko.pdf_utils import text
from pyhanko.pdf_utils.font import opentype
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers, fields
from pki import timestamps
from pyhanko.sign.ades.api import CAdESSignedAttrSpec
from pyhanko.sign.fields import SigSeedSubFilter, SigFieldSpec
from pyhanko.stamp import TextStampStyle
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore
from starlette import status

from dss_dummy_server.core.file import join_temp_path, temp_path
from pki.gost_pdf import GostSigner
from io import BytesIO
from pathlib import Path
from logging import getLogger

from pki.pdf.signer import GostPdfSigner


class SignatureSpec(BaseModel):
    name: str
    box: list[int, int, int, int]
    credential_id: str


class SignatureFieldsSpec(BaseModel):
    fields: list[SignatureSpec]


class LibreOfficeError(Exception):
    pass


def load_config(config_path: str = "/certomancer/example.yml") -> registry.CertomancerConfig:
    return registry.CertomancerConfig.from_file(config_path)


def load_certificate_store() -> SimpleCertificateStore:
    return SimpleCertificateStore()


def extract_field_spec(signature_spec: SignatureSpec, sig_field_name: str) -> SigFieldSpec:
    return SigFieldSpec(
        sig_field_name=sig_field_name,
        box=signature_spec.box
    )


TIME_STAMPING_URL = 'http://ca:9000/testing-ca/tsa/tsa'


class SigningEndpoint:
    def __init__(
        self,
        certomancer_config: registry.CertomancerConfig = load_config(),
    ):
        self.logger = getLogger(SigningEndpoint.__name__)
        self.certomancer_config = certomancer_config
        self.validation_context = self._validation_context()
        self.certificate_store = self.validation_context.certificate_registry
        self.time_stamping_client = timestamps.HTTPTimeStamper(TIME_STAMPING_URL)

        self.router = InferringRouter(prefix="/dss/v1")
        self.router.add_api_route("/sign_docx/", self.sign_docx_to_pdf, methods=["POST"])
        self.router.add_api_route("/sign_pdf/", self.sign_pdf, methods=["POST"])

    def _validation_context(self):
        pki_arch, cert_spec = self._parse_credential_id("testing-ca/interm")
        root_cert = pki_arch.get_cert(cert_spec.label)

        validation_context = ValidationContext(
            revocation_mode="hard-fail",
            allow_fetching=True,
            trust_roots=[root_cert]
        )

        return validation_context

    async def sign_docx_to_pdf(
        self,
        signatures_specs: list[SignatureSpec],
        document_id: str = Body(default=...)
    ):
        filepath = list(temp_path().glob(f"{document_id}.*"))

        if not filepath:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail='File is missing'
            )

        filepath = filepath[0]

        try:
            pdf_data = BytesIO(convert_docx_to_pdf(filepath))
        except LibreOfficeError as error:
            self.logger.error(error.args)
            raise HTTPException(
                status_code=400,
                detail="Error when converting file to PDF"
            )

        for spec in signatures_specs:
            responder_cert, responder_key = self.get_cert_and_key(spec.credential_id)

            algorithm = responder_key.algorithm
            if not self.validate_algorithm_id(algorithm):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f'The signature algorithm {algorithm} is unsupported'
                )

            signed_pdf = self.general_sign(
                responder_cert=responder_cert,
                responder_key=responder_key,
                data=pdf_data.getvalue(),
                field_spec=extract_field_spec(spec, sig_field_name=spec.name),
            )

            pdf_data = await signed_pdf

        filepath.unlink()
        return StreamingResponse(pdf_data, media_type="application/pdf")

    async def sign_pdf(
        self,
        signatures_specs: list[SignatureSpec],
        document_id: str = Body(default=...)
    ):
        filepath = list(temp_path().glob(f"{document_id}.*"))

        if not filepath:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail='File is missing'
            )

        filepath = filepath[0]

        pdf_data = BytesIO(filepath.read_bytes())
        for spec in signatures_specs:
            responder_cert, responder_key = self.get_cert_and_key(spec.credential_id)

            algorithm = responder_key.algorithm
            if not self.validate_algorithm_id(algorithm):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f'The signature algorithm {algorithm} is unsupported'
                )

            signed_pdf = self.general_sign(
                responder_cert=responder_cert,
                responder_key=responder_key,
                data=pdf_data.getvalue(),
                field_spec=extract_field_spec(spec, sig_field_name=spec.name),
            )

            pdf_data = await signed_pdf

        filepath.unlink()
        return StreamingResponse(pdf_data, media_type="application/pdf")

    def validate_algorithm_id(self, algorithm: str):
        return "gost" in algorithm

    async def general_sign(
        self,
        responder_cert: Certificate,
        responder_key: PrivateKeyInfo,
        data: bytes,
        field_spec: SigFieldSpec,
    ) -> BytesIO:
        in_buffer_document = BytesIO(data)

        signer = GostSigner(
            responder_cert, responder_key, self.certificate_store
        )
        writer = IncrementalPdfFileWriter(in_buffer_document)

        fields.append_signature_field(
            writer, sig_field_spec=field_spec
        )
        pdf_signer = GostPdfSigner(
            timestamper=self.time_stamping_client,
            signature_meta=signers.PdfSignatureMetadata(
                field_name=field_spec.sig_field_name,
                subfilter=SigSeedSubFilter.PADES,
                use_pades_lta=True,
                cades_signed_attr_spec=CAdESSignedAttrSpec(
                    timestamp_content=True,
                ),
            ),
            signer=signer,
            stamp_style=TextStampStyle(
                stamp_text=f'{field_spec.sig_field_name}\nПодписано: %(signer)s\n',
                border_width=0,
                text_box_style=text.TextBoxStyle(
                    font=opentype.GlyphAccumulatorFactory(
                        './thin_text.ttf',
                        ot_language_tag="RUS ",
                    ),
                ),
            ),
        )

        return await pdf_signer.async_sign_pdf(writer, in_place=True)

    def get_cert_and_key(self, credential_id: str) -> [Certificate, PrivateKeyInfo]:
        pki_arch, cert_spec = self._parse_credential_id(credential_id)

        try:
            responder_key = pki_arch.key_set.get_private_key(
                cert_spec.subject_key
            )
            responder_cert = pki_arch.get_cert(cert_spec.label)
        except ConfigurationError:
            # logger.error("Failed to obtain private key data", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f'Private key not found by {cert_spec.label}'
            )

        return responder_cert, responder_key

    def _parse_credential_id(self, cred_id: str) -> tuple[PKIArchitecture, CertificateSpec]:
        arch_id, cert_id = cred_id.split(sep='/', maxsplit=1)
        arch_label = ArchLabel(arch_id)
        try:
            cert_label = CertLabel(cert_id)
        except IndexError:
            raise HTTPException(status_code=404)

        try:
            pki_arch = self.certomancer_config.get_pki_arch(arch_label)
            cert_spec = pki_arch.get_cert_spec(cert_label)
        except CertomancerObjectNotFoundError:
            raise HTTPException(status_code=404)
        return pki_arch, cert_spec


def convert_docx_to_pdf(filepath: Path, timeout=None) -> bytes:
    temp_filename = f'{str(uuid.uuid4())}.pdf'
    temp_file = join_temp_path(temp_filename)
    args = [
        'libreoffice', '--headless', '--nologo', '--convert-to', 'pdf', '--outdir',
        temp_file.absolute(),
        filepath.absolute()
    ]

    process = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)

    filename = re.search('-> (.*?) using filter', process.stdout.decode())

    if filename is None:
        raise LibreOfficeError(process.stderr.decode(), process.stdout.decode(), process.returncode)

    temp_file = Path(filename.group(1))
    data_file = temp_file.read_bytes()
    temp_file.unlink()

    return data_file
