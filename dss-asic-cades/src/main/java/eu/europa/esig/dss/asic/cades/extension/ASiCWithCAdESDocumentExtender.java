package eu.europa.esig.dss.asic.cades.extension;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESFormatDetector;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.extension.AbstractDocumentExtender;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;

import java.util.Objects;

/**
 * ASiC with CAdES container specific implementation of a {@code eu.europa.esig.dss.spi.augmentation.DocumentExtender}.
 *
 */
public class ASiCWithCAdESDocumentExtender extends AbstractDocumentExtender<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> {

    /**
     * Empty constructor
     */
    ASiCWithCAdESDocumentExtender() {
        // empty
    }

    /**
     * Default constructor
     *
     * @param document {@link DSSDocument} to be extended
     */
    public ASiCWithCAdESDocumentExtender(final DSSDocument document) {
        Objects.requireNonNull(document, "Document to be extended cannot be null!");
        this.document = document;
    }

    @Override
    protected DocumentSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> initSignatureService() {
        Objects.requireNonNull(certificateVerifier, "CertificateVerifier cannot be null!");
        final ASiCWithCAdESService service = new ASiCWithCAdESService(certificateVerifier);
        service.setTspSource(tspSource);
        return service;
    }

    @Override
    public boolean isSupported(DSSDocument dssDocument) {
        return new ASiCWithCAdESFormatDetector().isSupportedASiC(dssDocument);
    }

    @Override
    protected ASiCWithCAdESSignatureParameters emptySignatureParameters() {
        return new ASiCWithCAdESSignatureParameters();
    }

    @Override
    protected boolean isSupportedParameters(SerializableSignatureParameters parameters) {
        return parameters instanceof ASiCWithCAdESSignatureParameters;
    }

    @Override
    protected SignatureForm getSignatureForm() {
        return SignatureForm.CAdES;
    }

}
