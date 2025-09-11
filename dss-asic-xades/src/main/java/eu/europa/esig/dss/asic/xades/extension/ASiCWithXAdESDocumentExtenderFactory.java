package eu.europa.esig.dss.asic.xades.extension;

import eu.europa.esig.dss.extension.SignedDocumentExtender;
import eu.europa.esig.dss.extension.SignedDocumentExtenderFactory;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * This class is used to check and load a corresponding {@code DocumentExtender} implementation
 * for a CAdES signature or signatures augmentation.
 *
 */
public class ASiCWithXAdESDocumentExtenderFactory implements SignedDocumentExtenderFactory {

    /**
     * Default constructor
     */
    public ASiCWithXAdESDocumentExtenderFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        return new ASiCWithXAdESDocumentExtender().isSupported(document);
    }

    @Override
    public SignedDocumentExtender create(DSSDocument document) {
        return new ASiCWithXAdESDocumentExtender(document);
    }

}
