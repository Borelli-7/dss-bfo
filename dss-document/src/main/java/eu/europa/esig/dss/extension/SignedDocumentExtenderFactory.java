package eu.europa.esig.dss.extension;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * This interface is used to analyze the format of the given {@code DSSDocument} and
 * create a corresponding implementation of {@code eu.europa.esig.dss.spi.augmentation.SignedDocumentExtender}
 *
 */
public interface SignedDocumentExtenderFactory {

    /**
     * This method tests if the current implementation of {@link SignedDocumentExtender}
     * supports the given document
     *
     * @param document
     *                 the document to be tested
     * @return true, if the {@link SignedDocumentExtender} supports the given document
     */
    boolean isSupported(DSSDocument document);

    /**
     * This method instantiates a {@link SignedDocumentExtender} with the given document
     *
     * @param document
     *                 the document to be used for the {@link SignedDocumentExtender}
     *                 creation
     * @return an instance of {@link SignedDocumentExtender} with the document
     */
    SignedDocumentExtender create(DSSDocument document);

}
