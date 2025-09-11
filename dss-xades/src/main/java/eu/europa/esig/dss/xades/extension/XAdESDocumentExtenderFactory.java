package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.extension.SignedDocumentExtender;
import eu.europa.esig.dss.extension.SignedDocumentExtenderFactory;
import eu.europa.esig.dss.model.DSSDocument;

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
    public SignedDocumentExtender create(DSSDocument document) {
        return new XAdESDocumentExtender(document);
    }

}
