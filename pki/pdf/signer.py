from typing import Optional

from cryptography.hazmat.primitives import hashes
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.writer import BasePdfFileWriter
from pyhanko.sign import SignatureObject
from pyhanko.sign.fields import SigSeedSubFilter, SigFieldSpec
from pyhanko.sign.general import SigningError, get_pyca_cryptography_hash, get_cms_hash_algo_for_mechanism
from pyhanko.sign.signers import constants
from pyhanko.sign.signers.cms_embedder import PdfCMSEmbedder, SigObjSetup, SigAppearanceSetup
from pyhanko.sign.signers.pdf_cms import PdfCMSSignedAttributes, Signer
from pyhanko.sign.signers.pdf_signer import PdfSigningSession, PreSignValidationStatus, PdfSigner, PdfSignatureMetadata, \
    PostSignInstructions, PdfTBSDocument, SigDSSPlacementPreference

from gostcrypto import gosthash
from pyhanko.sign.timestamps import TimeStamper
from pyhanko.stamp import BaseStampStyle
from pyhanko_certvalidator import PathBuildingError
from pyhanko_certvalidator.errors import PathValidationError

from pki.pdf.byterange import GostSignatureObject
from pki.pdf.general import get_cryptography_hash, restore_oid_hash


class GostPdfSigningSession(PdfSigningSession):
    async def estimate_signature_container_size(
            self, validation_info: PreSignValidationStatus, tight=False):
        md_algorithm = self.md_algorithm
        signature_meta = self.pdf_signer.signature_meta
        signer = self.pdf_signer.signer

        if signer.signing_cert is None:
            raise SigningError(
                "Automatic signature size estimation is not available without "
                "a signer's certificate. Space must be allocated manually "
                "using bytes_reserved=..."
            )

        spec_algorithm = get_cryptography_hash(md_algorithm)
        test_md = bytes(gosthash.new(spec_algorithm).digest())

        signed_attrs = PdfCMSSignedAttributes(
            signing_time=self.system_time,
            adobe_revinfo_attr=(
                None if validation_info is None else
                validation_info.adobe_revinfo_attr
            ),
            cades_signed_attrs=signature_meta.cades_signed_attr_spec
        )
        test_signature_cms = await signer.async_sign(
            test_md, md_algorithm, use_pades=self.use_pades,
            dry_run=True, timestamper=self.timestamper,
            signed_attr_settings=signed_attrs
        )

        # Note: multiply by 2 to account for the fact that this byte dump
        # will be embedded into the resulting PDF as a hexadecimal
        # string
        test_len = len(test_signature_cms.dump()) * 2

        if tight:
            bytes_reserved = test_len
        else:
            # External actors such as timestamping servers can't be relied on to
            # always return exactly the same response, so we build in a 50%
            # error margin (+ ensure that bytes_reserved is even)
            bytes_reserved = test_len + 2 * (test_len // 4)
        return bytes_reserved

    def prepare_tbs_document(self, validation_info: PreSignValidationStatus,
                             bytes_reserved, appearance_text_params=None) \
            -> 'PdfTBSDocument':
        """
        Set up the signature appearance (if necessary) and signature dictionary
        in the PDF file, to put the document in its final pre-signing state.

        :param validation_info:
            Validation information collected prior to signing.
        :param bytes_reserved:
            Bytes to reserve for the signature container.
        :param appearance_text_params:
            Optional text parameters for the signature appearance content.
        :return:
            A :class:`.PdfTBSDocument` describing the document in its final
            pre-signing state.
        """

        pdf_signer = self.pdf_signer
        signature_meta = self.pdf_signer.signature_meta
        if self.sv_spec is not None:
            # process the field's seed value constraints
            self._enforce_seed_value_constraints(
                None if validation_info is None else
                validation_info.signer_path
            )

        signer = pdf_signer.signer
        embed_roots = signer.embed_roots
        # take care of DSS updates, if they have to happen now
        dss_settings = signature_meta.dss_settings
        if self.use_pades and validation_info is not None:
            # Check consistency of settings
            dss_settings.assert_viable()
            if dss_settings.placement \
                    == SigDSSPlacementPreference.TOGETHER_WITH_SIGNATURE:
                from pyhanko.sign import validation
                pdf_out = self.pdf_out
                # source info directly from the validation_info object
                # for consistency
                # NOTE: we have to disable VRI in this scenario
                validation.DocumentSecurityStore.supply_dss_in_writer(
                    pdf_out, sig_contents=None,
                    paths=validation_info.validation_paths,
                    ocsps=validation_info.ocsps_to_embed,
                    crls=validation_info.crls_to_embed,
                    embed_roots=embed_roots
                )

        md_algorithm = self.md_algorithm

        sig_mdp_setup = self._apply_locking_rules()

        # Prepare instructions to the CMS writer to set up the
        # (PDF) signature object and its appearance
        system_time = self.system_time
        name_specified = signature_meta.name
        sig_appearance = SigAppearanceSetup(
            style=pdf_signer.stamp_style,
            name=name_specified or signer.subject_name,
            timestamp=system_time, text_params=appearance_text_params
        )
        sig_obj = GostSignatureObject(
            bytes_reserved=bytes_reserved, subfilter=self.subfilter,
            timestamp=system_time,
            name=name_specified if name_specified else None,
            location=signature_meta.location, reason=signature_meta.reason,
        )

        # Pass in the SignatureObject settings
        self.cms_writer.send(SigObjSetup(
            sig_placeholder=sig_obj,
            mdp_setup=sig_mdp_setup,
            appearance_setup=sig_appearance
        ))

        # At this point, the document is in its final pre-signing state

        # Last job: prepare instructions for the post-signing workflow
        signature_meta = pdf_signer.signature_meta
        validation_context = signature_meta.validation_context
        post_signing_instr = doc_timestamper = None
        if self.use_pades and signature_meta.embed_validation_info:
            if signature_meta.use_pades_lta:
                doc_timestamper = self.timestamper
            # if necessary/supported, extract a file access credential
            # to perform post-signing operations later
            if self.pdf_out.security_handler is not None:
                credential = self.pdf_out.security_handler.extract_credential()
            else:
                credential = None
            post_signing_instr = PostSignInstructions(
                validation_info=validation_info,
                # use the same algorithm
                # TODO make this configurable? Some TSAs only allow one choice
                #  of MD, and forcing our signers to use the same one to handle
                #  might be overly restrictive (esp. for things like EdDSA where
                #  the MD is essentially fixed)
                timestamp_md_algorithm=md_algorithm,
                timestamper=doc_timestamper,
                timestamp_field_name=signature_meta.timestamp_field_name,
                dss_settings=signature_meta.dss_settings,
                tight_size_estimates=signature_meta.tight_size_estimates,
                embed_roots=embed_roots,
                file_credential=credential
            )
        return PdfTBSDocument(
            cms_writer=self.cms_writer, signer=pdf_signer.signer,
            md_algorithm=md_algorithm, timestamper=self.timestamper,
            use_pades=self.use_pades,
            post_sign_instructions=post_signing_instr,
            validation_context=validation_context
        )


class GostPdfSigner(PdfSigner):
    def init_signing_session(self, pdf_out: BasePdfFileWriter,
                             existing_fields_only=False) -> 'PdfSigningSession':
        """
        Initialise a signing session with this :class:`.PdfSigner` for a
        specified PDF file writer.

        This step in the signing process handles all field-level operations
        prior to signing: it creates the target form field if necessary, and
        makes sure the seed value dictionary gets processed.

        See also :meth:`digest_doc_for_signing` and :meth:`sign_pdf`.

        :param pdf_out:
            The writer containing the PDF file to be signed.
        :param existing_fields_only:
            If ``True``, never create a new empty signature field to contain
            the signature.
            If ``False``, a new field may be created if no field matching
            :attr:`~.PdfSignatureMetadata.field_name` exists.
        :return:
            A :class:`.PdfSigningSession` object modelling the signing session
            in its post-setup stage.
        """

        if isinstance(pdf_out, IncrementalPdfFileWriter):
            # ensure we're not signing a hybrid reference doc
            prev = pdf_out.prev
            if prev.strict and prev.xrefs.hybrid_xrefs_present:
                raise SigningError(
                    "Attempting to sign document with hybrid cross-reference "
                    "sections while hybrid xrefs are disabled"
                )

        timestamper = self.default_timestamper

        signature_meta: PdfSignatureMetadata = self.signature_meta

        cms_writer = PdfCMSEmbedder(
            new_field_spec=self.new_field_spec
        ).write_cms(
            field_name=signature_meta.field_name, writer=pdf_out,
            existing_fields_only=existing_fields_only
        )

        # let the CMS writer put in a field for us, if necessary
        sig_field_ref = next(cms_writer)

        sig_field = sig_field_ref.get_object()

        # Fetch seed values (if present) to prepare for signing
        sv_spec = self._retrieve_seed_value_spec(sig_field)

        # Check DocMDP settings to see if we're allowed to add a signature
        if isinstance(pdf_out, IncrementalPdfFileWriter):
            self._enforce_certification_constraints(pdf_out.prev)

        md_algorithm = self._select_md_algorithm(sv_spec)
        self.register_extensions(pdf_out, md_algorithm=md_algorithm)

        ts_required = sv_spec is not None and sv_spec.timestamp_required
        if ts_required and timestamper is None:
            timestamper = sv_spec.build_timestamper()

        subfilter = signature_meta.subfilter
        if subfilter is None:
            if sv_spec is not None and sv_spec.subfilters:
                subfilter = sv_spec.subfilters[0]
            else:
                subfilter = SigSeedSubFilter.ADOBE_PKCS7_DETACHED

        session = GostPdfSigningSession(
            self, pdf_out, cms_writer, sig_field, md_algorithm, timestamper,
            subfilter, sv_spec=sv_spec
        )

        return session
