package eu.europa.esig.dss.spi.extension;

import eu.europa.esig.dss.enumerations.SignatureProfile;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

import java.util.List;

/**
 * This class performs a signature augmentation to the specified target augmentation level,
 * respectively to the signature's format, which is determined in the runtime during the method execution.
 * <p>
 * This class can be used as an alternative to the {@code eu.europa.esig.dss.signature.DocumentSignatureService#extendDocument}
 * which requires the client to know the original signature format before the method execution.
 *
 */
public interface DocumentExtender {

    /**
     * Sets a CertificateVerifier providing a configuration for validation of certificates
     * within the original signature or signatures.
     *
     * @param certificateVerifier {@link CertificateVerifier}
     */
    void setCertificateVerifier(CertificateVerifier certificateVerifier);

    /**
     * Source to be used for time-stamp requests, when applicable (e.g. BASELINE-T or BASELINE-LTA profile extension)
     *
     * @param tspSource {@link TSPSource}
     */
    void setTspSource(TSPSource tspSource);

    /**
     * Checks if the document is supported by the current signature extender
     *
     * @param dssDocument {@link DSSDocument} to check
     * @return TRUE if the document is supported, FALSE otherwise
     */
    boolean isSupported(DSSDocument dssDocument);

    /**
     * Performs augmentation of all signatures within the provided document according
     * to the specified target {@code signatureProfile}.
     *
     * @param signatureProfile {@link SignatureProfile} identifying the desired target augmentation level
     * @return {@link DSSDocument} containing the augmented signatures, if the augmentation succeeds.
     */
    DSSDocument extendDocument(SignatureProfile signatureProfile);

    /**
     * Performs augmentation of all signatures of a detached format within the provided document according
     * to the specified target {@code signatureProfile}.
     *
     * @param signatureProfile {@link SignatureProfile} identifying the desired target augmentation level
     * @param detachedContents list of {@link DSSDocument}s representing a signed content in case of a detached signature
     * @return {@link DSSDocument} containing the augmented signatures, if the augmentation succeeds.
     */
    DSSDocument extendDocument(SignatureProfile signatureProfile, List<DSSDocument> detachedContents);

    /**
     * Performs augmentation of all signatures within the provided document according
     * to the specified {@code augmentationParameters}, with format specific {@code extensionParameters}.
     * <p>
     * If {@code explicitParameters} are provided, and they contain an implementation of parameters matching
     * the current signature format, those signature parameters will be used explicitly on this signature augmentation.
     * This can be useful when a signature augmentation process for a certain signature format should take
     * into account particular signature constraints (i.e. /Contents size for a PAdES document time-stamp, etc.).
     * <p>
     * NOTE: If the matching implementation of extension parameters found, and it contains {@code signatureLevel}
     *       and/or {@code detachedContents} definition, the existing values will be used.
     *       Otherwise, the content of the extension parameters will be overwritten respectively.
     *
     * @param signatureProfile {@link SignatureProfile} identifying the desired target augmentation level
     * @param extensionParameters (optional) {@link SerializableSignatureParameters} containing format specific requirements
     * @return {@link DSSDocument} containing the augmented signatures, if the augmentation succeeds.
     */
    DSSDocument extendDocument(SignatureProfile signatureProfile, SerializableSignatureParameters... extensionParameters);

    /**
     * Performs augmentation of all signatures of a detached format within the provided document according
     * to the specified target {@code signatureProfile}, with format specific {@code extensionParameters}.
     * <p>
     * If {@code explicitParameters} are provided, and they contain an implementation of parameters matching
     * the current signature format, those signature parameters will be used explicitly on this signature augmentation.
     * This can be useful when a signature augmentation process for a certain signature format should take
     * into account particular signature constraints (i.e. /Contents size for a PAdES document time-stamp, etc.).
     * <p>
     * NOTE: If the matching implementation of extension parameters found, and it contains {@code signatureLevel}
     *       and/or {@code detachedContents} definition, the existing values will be used.
     *       Otherwise, the content of the extension parameters will be overwritten respectively.
     *
     * @param signatureProfile {@link SignatureProfile} identifying the desired target augmentation level
     * @param detachedContents list of {@link DSSDocument}s representing a signed content in case of a detached signature
     * @param extensionParameters (optional) {@link SerializableSignatureParameters} containing format specific requirements
     * @return {@link DSSDocument} containing the augmented signatures, if the augmentation succeeds.
     */
    DSSDocument extendDocument(SignatureProfile signatureProfile, List<DSSDocument> detachedContents,
                               SerializableSignatureParameters... extensionParameters);

}
