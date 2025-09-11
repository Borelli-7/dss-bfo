package eu.europa.esig.dss.asic.cades.extension;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.extension.DocumentExtender;
import eu.europa.esig.dss.spi.extension.SignedDocumentExtenderFactory;

/**
 * This class is used to check and load a corresponding {@code DocumentExtender} implementation
 * for a CAdES signature or signatures augmentation.
 *
 */
public class ASiCWithCAdESDocumentExtenderFactory implements SignedDocumentExtenderFactory {

    /**
     * Default constructor
     */
    public ASiCWithCAdESDocumentExtenderFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        return new ASiCWithCAdESDocumentExtender().isSupported(document);
    }

    @Override
    public DocumentExtender create(DSSDocument document) {
        return new ASiCWithCAdESDocumentExtender(document);
    }

}
