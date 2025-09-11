package eu.europa.esig.dss.extension;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.extension.DocumentExtender;
import eu.europa.esig.dss.spi.extension.SignedDocumentExtenderFactory;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

import java.util.Objects;
import java.util.ServiceLoader;

/**
 * This class contains common code for signature augmentation utilities.
 *
 */
public abstract class SignedDocumentExtender implements DocumentExtender {

    /**
     * The reference to the certificate verifier. The current DSS implementation
     * proposes {@link eu.europa.esig.dss.spi.validation.CommonCertificateVerifier}.
     * This verifier encapsulates the references to different sources used in the
     * signature validation process.
     */
    protected CertificateVerifier certificateVerifier;

    /**
     * The source to be used for a timestamp token request, when applicable.
     */
    protected TSPSource tspSource;

    /**
     * Empty constructor
     */
    protected SignedDocumentExtender() {
        // empty
    }

    /**
     * This method guesses the document format and returns an appropriate
     * document reader.
     *
     * @param dssDocument
     *            The instance of {@code DSSDocument} to validate
     * @return returns the specific instance of {@code DocumentReader} in terms
     *         of the document type
     */
    public static DocumentExtender fromDocument(final DSSDocument dssDocument) {
        Objects.requireNonNull(dssDocument, "DSSDocument is null");
        ServiceLoader<SignedDocumentExtenderFactory> serviceLoaders = ServiceLoader.load(SignedDocumentExtenderFactory.class);
        for (SignedDocumentExtenderFactory factory : serviceLoaders) {
            if (factory.isSupported(dssDocument)) {
                return factory.create(dssDocument);
            }
        }
        throw new UnsupportedOperationException("Document format not recognized/handled");
    }

    @Override
    public void setCertificateVerifier(CertificateVerifier certificateVerifier) {
        this.certificateVerifier = certificateVerifier;
    }

    @Override
    public void setTspSource(TSPSource tspSource) {
        this.tspSource = tspSource;
    }

}
