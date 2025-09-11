package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.extension.SignedDocumentExtenderFactory;
import eu.europa.esig.dss.spi.extension.DocumentExtender;

/**
 * This class is used to check and load a corresponding {@code DocumentExtender} implementation
 * for a XAdES signature or signatures augmentation.
 *
 */
public class XAdESDocumentExtenderFactory implements SignedDocumentExtenderFactory {

    /**
     * Default constructor
     */
    public XAdESDocumentExtenderFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        return new XAdESDocumentExtender().isSupported(document);
    }

    @Override
    public DocumentExtender create(DSSDocument document) {
        return new XAdESDocumentExtender(document);
    }

}
