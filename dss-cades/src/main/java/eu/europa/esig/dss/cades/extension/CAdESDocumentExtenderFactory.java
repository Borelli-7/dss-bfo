package eu.europa.esig.dss.cades.extension;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.extension.SignedDocumentExtenderFactory;
import eu.europa.esig.dss.spi.extension.DocumentExtender;

/**
 * This class is used to check and load a corresponding {@code DocumentExtender} implementation
 * for a CAdES signature or signatures augmentation.
 *
 */
public class CAdESDocumentExtenderFactory implements SignedDocumentExtenderFactory {

    /**
     * Default constructor
     */
    public CAdESDocumentExtenderFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        return new CAdESDocumentExtender().isSupported(document);
    }

    @Override
    public DocumentExtender create(DSSDocument document) {
        return new CAdESDocumentExtender(document);
    }

}
