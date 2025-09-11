package eu.europa.esig.dss.jades.extension;

import eu.europa.esig.dss.extension.SignedDocumentExtender;
import eu.europa.esig.dss.extension.SignedDocumentExtenderFactory;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * This class is used to check and load a corresponding {@code DocumentExtender} implementation
 * for a JAdES signature or signatures augmentation.
 *
 */
public class JAdESDocumentExtenderFactory implements SignedDocumentExtenderFactory {

    /**
     * Default constructor
     */
    public JAdESDocumentExtenderFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        return new JAdESDocumentExtender().isSupported(document);
    }

    @Override
    public SignedDocumentExtender create(DSSDocument document) {
        return new JAdESDocumentExtender(document);
    }

}
