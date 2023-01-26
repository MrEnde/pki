from io import BytesIO

from pyhanko.pdf_utils import misc
from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.writer import BasePdfFileWriter
from pyhanko.sign.signers.pdf_byterange import PreparedByteRangeDigest, DERPlaceholder, SigByteRangeObject, \
    PdfByteRangeDigest, SignatureObject

from gostcrypto import gosthash

from pki.pdf.general import get_cryptography_hash
from pki.pdf.pdf_embedded import chunked_digest

from copy import copy


class GostSignatureObject(SignatureObject):
    """
    General class to model a PDF Dictionary that has a ``/ByteRange`` entry
    and a another data entry (named ``/Contents`` by default) that will contain
    a value based on a digest computed over said ``/ByteRange``.
    The ``/ByteRange`` will cover the entire file, except for the value of the
    data entry itself.

    .. danger::
        This is internal API.

    :param data_key:
        Name of the data key, which is ``/Contents`` by default.
    :param bytes_reserved:
        Number of bytes to reserve for the contents placeholder.
        If ``None``, a generous default is applied, but you should try to
        estimate the size as accurately as possible.
    """

    def fill(self, writer: BasePdfFileWriter, md_algorithm,
             in_place=False, output=None, chunk_size=misc.DEFAULT_CHUNK_SIZE):
        """
        Generator coroutine that handles the document hash computation and
        the actual filling of the placeholder data.

        .. danger::
            This is internal API; you should use use :class:`.PdfSigner`
            wherever possible. If you *really* need fine-grained control,
            use :class:`~pyhanko.sign.signers.cms_embedder.PdfCMSEmbedder`
            instead.
        """

        if in_place:
            if not isinstance(writer, IncrementalPdfFileWriter):
                raise TypeError(
                    "in_place is only meaningful for incremental writers."
                )  # pragma: nocover
            output = writer.prev.stream
            writer.write_in_place()
        else:
            output = misc.prepare_rw_output_stream(output)

            writer.write(output)

        # retcon time: write the proper values of the /ByteRange entry
        #  in the signature object
        eof = output.tell()
        sig_start, sig_end = self.contents.offsets
        self.byte_range.fill_offsets(output, sig_start, sig_end, eof)

        # compute the digests
        md_spec = get_cryptography_hash(md_algorithm)
        md = gosthash.new(md_spec)

        output_buffer = None
        if isinstance(output, BytesIO):
            output_buffer = output.getbuffer()
        else:
            try:
                output_buffer = memoryview(output)
            except (TypeError, IOError):
                pass

        if output_buffer is not None:
            # these are memoryviews, so slices should not copy stuff around
            #   (also, the interface files for pyca/cryptography don't specify
            #    that memoryviews are allowed, but they are)
            # noinspection PyTypeChecker
            md.update(bytes(output_buffer[:sig_start]))
            # noinspection PyTypeChecker
            md.update(bytes(output_buffer[sig_end:eof]))
            output_buffer.release()
        else:
            temp_buffer = bytearray(chunk_size)
            output.seek(0)
            chunked_digest(temp_buffer, output, md, max_read=sig_start)
            output.seek(sig_end)
            chunked_digest(temp_buffer, output, md, max_read=eof-sig_end)

        digest_value = bytes(md.digest())

        prepared_br_digest = PreparedByteRangeDigest(
            document_digest=digest_value,
            reserved_region_start=sig_start, reserved_region_end=sig_end
        )
        cms_data = yield prepared_br_digest, output
        yield prepared_br_digest.fill_with_cms(output, cms_data)
