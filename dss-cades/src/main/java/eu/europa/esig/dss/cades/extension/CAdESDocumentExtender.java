package eu.europa.esig.dss.cades.extension;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.cades.validation.CMSDocumentAnalyzerFactory;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.extension.AbstractDocumentExtender;

import java.util.Objects;

/**
 * CAdES specific implementation of a {@code eu.europa.esig.dss.spi.augmentation.DocumentExtender}.
 *
 */
public class CAdESDocumentExtender extends AbstractDocumentExtender<CAdESSignatureParameters, CAdESTimestampParameters> {

    /**
     * Empty constructor
     */
    CAdESDocumentExtender() {
        // empty
    }

    /**
     * Default constructor
     *
     * @param document {@link DSSDocument} to be extended
     */
    public CAdESDocumentExtender(final DSSDocument document) {
        Objects.requireNonNull(document, "Document to be extended cannot be null!");
        this.document = document;
    }

    @Override
    protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> createSignatureService() {
        Objects.requireNonNull(certificateVerifier, "Please provide CertificateVerifier or corresponding CAdESService!");
        final CAdESService service = new CAdESService(certificateVerifier);
        service.setTspSource(tspSource);
        return service;
    }

    @Override
    public boolean isSupported(DSSDocument dssDocument) {
        return new CMSDocumentAnalyzerFactory().isSupported(dssDocument);
    }

    @Override
    protected CAdESSignatureParameters emptySignatureParameters() {
        return new CAdESSignatureParameters();
    }

    @Override
    protected boolean isSupportedParameters(SerializableSignatureParameters parameters) {
        return parameters instanceof CAdESSignatureParameters;
    }

    @Override
    protected boolean isSupportedService(DocumentSignatureService<?, ?> service) {
        return service instanceof CAdESService;
    }

    @Override
    public SignatureForm getSignatureForm() {
        return SignatureForm.CAdES;
    }

}
