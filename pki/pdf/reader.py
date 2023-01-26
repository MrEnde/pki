from pyhanko.pdf_utils.reader import PdfFileReader
from pki.pdf.pdf_embedded import GostEmbeddedPdfSignature


class GostPdfFileReader(PdfFileReader):

    @property
    def embedded_signatures(self):
        """
        :return:
            The signature objects embedded in this document, in signing order;
            see :class:`~pyhanko.sign.validation.EmbeddedPdfSignature`.
        """
        if self._embedded_signatures is not None:
            return self._embedded_signatures
        from pyhanko.sign.fields import enumerate_sig_fields

        sig_fields = enumerate_sig_fields(self, filled_status=True)

        result = sorted(
            (
                GostEmbeddedPdfSignature(self, sig_field, fq_name)
                for fq_name, sig_obj, sig_field in sig_fields
            ), key=lambda emb: emb.signed_revision
        )
        self._embedded_signatures = result
        return result
