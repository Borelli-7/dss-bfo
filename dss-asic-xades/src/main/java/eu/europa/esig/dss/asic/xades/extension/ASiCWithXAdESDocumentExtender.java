package eu.europa.esig.dss.asic.xades.extension;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESFormatDetector;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.extension.AbstractDocumentExtender;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;

import java.util.Objects;

/**
 * ASiC with XAdES container specific implementation of a {@code eu.europa.esig.dss.spi.augmentation.DocumentExtender}.
 *
 */
public class ASiCWithXAdESDocumentExtender extends AbstractDocumentExtender<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> {

    /**
     * Empty constructor
     */
    ASiCWithXAdESDocumentExtender() {
        // empty
    }

    /**
     * Default constructor
     *
     * @param document {@link DSSDocument} to be extended
     */
    public ASiCWithXAdESDocumentExtender(final DSSDocument document) {
        Objects.requireNonNull(document, "Document to be extended cannot be null!");
        this.document = document;
    }

    @Override
    protected DocumentSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> initSignatureService() {
        Objects.requireNonNull(certificateVerifier, "CertificateVerifier cannot be null!");
        final ASiCWithXAdESService service = new ASiCWithXAdESService(certificateVerifier);
        service.setTspSource(tspSource);
        return service;
    }

    @Override
    public boolean isSupported(DSSDocument dssDocument) {
        return new ASiCWithXAdESFormatDetector().isSupportedASiC(dssDocument);
    }

    @Override
    protected ASiCWithXAdESSignatureParameters emptySignatureParameters() {
        return new ASiCWithXAdESSignatureParameters();
    }

    @Override
    protected boolean isSupportedParameters(SerializableSignatureParameters parameters) {
        return parameters instanceof ASiCWithXAdESSignatureParameters;
    }

    @Override
    protected SignatureForm getSignatureForm() {
        return SignatureForm.XAdES;
    }

}
