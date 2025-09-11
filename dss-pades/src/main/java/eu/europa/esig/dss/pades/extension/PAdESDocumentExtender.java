package eu.europa.esig.dss.pades.extension;

import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.extension.AbstractDocumentExtender;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PDFDocumentAnalyzerFactory;
import eu.europa.esig.dss.signature.DocumentSignatureService;

import java.util.Objects;

/**
 * PAdES specific implementation of a {@code eu.europa.esig.dss.spi.augmentation.DocumentExtender}.
 *
 */
public class PAdESDocumentExtender extends AbstractDocumentExtender<PAdESSignatureParameters, PAdESTimestampParameters> {

    /**
     * Empty constructor
     */
    PAdESDocumentExtender() {
        // empty
    }

    /**
     * Default constructor
     *
     * @param document {@link DSSDocument} to be extended
     */
    public PAdESDocumentExtender(final DSSDocument document) {
        Objects.requireNonNull(document, "Document to be extended cannot be null!");
        this.document = document;
    }

    @Override
    protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> createSignatureService() {
        Objects.requireNonNull(certificateVerifier, "Please provide CertificateVerifier or corresponding PAdESService!");
        final PAdESService service = new PAdESService(certificateVerifier);
        service.setTspSource(tspSource);
        return service;
    }

    @Override
    public boolean isSupported(DSSDocument dssDocument) {
        return new PDFDocumentAnalyzerFactory().isSupported(dssDocument);
    }

    @Override
    protected PAdESSignatureParameters emptySignatureParameters() {
        return new PAdESSignatureParameters();
    }

    @Override
    protected boolean isSupportedParameters(SerializableSignatureParameters parameters) {
        return parameters instanceof PAdESSignatureParameters;
    }

    @Override
    protected boolean isSupportedService(DocumentSignatureService<?, ?> service) {
        return service instanceof PAdESService;
    }

    @Override
    public SignatureForm getSignatureForm() {
        return SignatureForm.PAdES;
    }

}
