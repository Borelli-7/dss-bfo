package eu.europa.esig.dss.xades;

import eu.europa.esig.dss.model.DSSDocument;

import java.util.List;

/**
 * XAdES signature creation profile
 *
 */
public interface XAdESSignatureProfile extends SignatureProfile {

    /**
     * Creates a signature of the defines profile for signing a document
     *
     * @param toSignDocument {@link DSSDocument} to be signed
     * @param parameters {@link XAdESSignatureParameters}
     * @param signatureValue signature value
     * @return {@link DSSDocument} signature document
     */
    DSSDocument signDocument(DSSDocument toSignDocument, XAdESSignatureParameters parameters, byte[] signatureValue);

    /**
     * Creates a signature of the defines profile for signing a list of documents
     *
     * @param toSignDocuments a list of {@link DSSDocument}s to be signed
     * @param parameters {@link XAdESSignatureParameters}
     * @param signatureValue signature value
     * @return {@link DSSDocument} signature document
     */
    DSSDocument signDocument(List<DSSDocument> toSignDocuments, XAdESSignatureParameters parameters, byte[] signatureValue);

}
