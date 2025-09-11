package eu.europa.esig.dss.pades.extension;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.extension.SignedDocumentExtenderFactory;
import eu.europa.esig.dss.spi.extension.DocumentExtender;

/**
 * This class is used to check and load a corresponding {@code DocumentExtender} implementation
 * for a PAdES signature or signatures augmentation.
 *
 */
public class PAdESDocumentExtenderFactory implements SignedDocumentExtenderFactory {

    /**
     * Default constructor
     */
    public PAdESDocumentExtenderFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        return new PAdESDocumentExtender().isSupported(document);
    }

    @Override
    public DocumentExtender create(DSSDocument document) {
        return new PAdESDocumentExtender(document);
    }

}
