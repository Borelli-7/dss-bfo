package eu.europa.esig.dss.model.tls;

import eu.europa.esig.dss.model.x509.CertificateToken;

import java.util.List;

/**
 * This class represents information obtained from a remote server as the result of the TLS/SSL handshake.
 *
 */
public class TLSCertificates {

    /** Collection of a certificate tokens returned after TLS/SSL handshake */
    private List<CertificateToken> certificates;

    /** The value of the "Link" response header with a rel value of tls-certificate-binding */
    private String tlsCertificateBindingUrl;

    /**
     * Default constructor
     */
    public TLSCertificates() {
        // empty
    }

    /**
     * Gets a list of certificates returned by a remote server during the TLS/SSL handshake
     *
     * @return a list of {@link CertificateToken}s
     */
    public List<CertificateToken> getCertificates() {
        return certificates;
    }

    /**
     * Sets a list of certificates returned by a remote server during the TLS/SSL handshake
     *
     * @param certificates a list of {@link CertificateToken}s
     */
    public void setCertificates(List<CertificateToken> certificates) {
        this.certificates = certificates;
    }

    /**
     * Gets value of the "Link" response header with a rel value of tls-certificate-binding.
     * This URL is used to extract a TLS/SSL binding signature.
     *
     * @return {@link String}
     */
    public String getTLSCertificateBindingUrl() {
        return tlsCertificateBindingUrl;
    }

    /**
     * Sets value of the "Link" response header with a rel value of tls-certificate-binding.
     * This URL is used to extract a TLS/SSL binding signature.
     *
     * @param tlsCertificateBindingUrl {@link String}
     */
    public void setTLSCertificateBindingUrl(String tlsCertificateBindingUrl) {
        this.tlsCertificateBindingUrl = tlsCertificateBindingUrl;
    }

}
