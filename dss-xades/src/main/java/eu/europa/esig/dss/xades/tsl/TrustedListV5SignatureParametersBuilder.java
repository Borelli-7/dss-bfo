package eu.europa.esig.dss.xades.tsl;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;

/**
 * Creates Signature parameters for a Trusted List V5 creation
 * <p>
 * NOTE: the same instance of SignatureParameters shall be used on calls
 * {@code DocumentSignatureService.getDataToSign(...)} and {@code DocumentSignatureService.signDocument(...)}
 *
 */
public class TrustedListV5SignatureParametersBuilder extends AbstractTrustedListSignatureParametersBuilder {

    /**
     * The constructor to build Signature Parameters for a Trusted List V5 signing with respect to ETSI TS 119 612
     *
     * @param signingCertificate {@link CertificateToken} to be used for a signature creation
     * @param tlXmlDocument      {@link DSSDocument} Trusted List XML document to be signed
     */
    public TrustedListV5SignatureParametersBuilder(CertificateToken signingCertificate, DSSDocument tlXmlDocument) {
        super(signingCertificate, tlXmlDocument);
    }

    @Override
    public TrustedListV5SignatureParametersBuilder setReferenceId(String referenceId) {
        return (TrustedListV5SignatureParametersBuilder) super.setReferenceId(referenceId);
    }

    @Override
    public TrustedListV5SignatureParametersBuilder setReferenceDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        return (TrustedListV5SignatureParametersBuilder) super.setReferenceDigestAlgorithm(digestAlgorithm);
    }

    @Override
    public TrustedListV5SignatureParametersBuilder setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        return (TrustedListV5SignatureParametersBuilder) super.setDigestAlgorithm(digestAlgorithm);
    }

    @Override
    public TrustedListV5SignatureParametersBuilder setEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
        return (TrustedListV5SignatureParametersBuilder) super.setEncryptionAlgorithm(encryptionAlgorithm);
    }

    @Override
    public TrustedListV5SignatureParametersBuilder setBLevelParams(BLevelParameters bLevelParams) {
        return (TrustedListV5SignatureParametersBuilder) super.setBLevelParams(bLevelParams);
    }

    @Override
    protected boolean isEn319132() {
        return false;
    }

    @Override
    protected Integer getTargetTLVersion() {
        return 5;
    }

}
