package eu.europa.esig.dss.spi.extension;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * This interface is used to analyze the format of the given {@code DSSDocument} and
 * create a corresponding implementation of {@code eu.europa.esig.dss.spi.augmentation.SignedDocumentExtender}
 *
 */
public interface SignedDocumentExtenderFactory {

    /**
     * This method tests if the current implementation of {@link DocumentExtender}
     * supports the given document
     *
     * @param document
     *                 the document to be tested
     * @return true, if the {@link DocumentExtender} supports the given document
     */
    boolean isSupported(DSSDocument document);

    /**
     * This method instantiates a {@link DocumentExtender} with the given document
     *
     * @param document
     *                 the document to be used for the {@link DocumentExtender}
     *                 creation
     * @return an instance of {@link DocumentExtender} with the document
     */
    DocumentExtender create(DSSDocument document);

}
