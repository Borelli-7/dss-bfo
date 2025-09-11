package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.extension.AbstractDocumentExtender;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.xades.validation.XMLDocumentAnalyzerFactory;

import java.util.Objects;

/**
 * XAdES specific implementation of a {@code eu.europa.esig.dss.spi.augmentation.DocumentExtender}.
 *
 */
public class XAdESDocumentExtender extends AbstractDocumentExtender<XAdESSignatureParameters, XAdESTimestampParameters> {

    /**
     * Empty constructor
     */
    XAdESDocumentExtender() {
        // empty
    }

    /**
     * Default constructor
     *
     * @param document {@link DSSDocument} to be extended
     */
    public XAdESDocumentExtender(final DSSDocument document) {
        Objects.requireNonNull(document, "Document to be extended cannot be null!");
        this.document = document;
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> initSignatureService() {
        Objects.requireNonNull(certificateVerifier, "CertificateVerifier cannot be null!");
        final XAdESService service = new XAdESService(certificateVerifier);
        service.setTspSource(tspSource);
        return service;
    }

    @Override
    public boolean isSupported(DSSDocument dssDocument) {
        return new XMLDocumentAnalyzerFactory().isSupported(dssDocument);
    }

    @Override
    protected XAdESSignatureParameters emptySignatureParameters() {
        return new XAdESSignatureParameters();
    }

    @Override
    protected boolean isSupportedParameters(SerializableSignatureParameters parameters) {
        return parameters instanceof XAdESSignatureParameters;
    }

    @Override
    protected SignatureForm getSignatureForm() {
        return SignatureForm.XAdES;
    }

}
