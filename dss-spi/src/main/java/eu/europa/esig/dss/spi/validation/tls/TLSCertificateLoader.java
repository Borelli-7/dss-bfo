package eu.europa.esig.dss.spi.validation.tls;

import eu.europa.esig.dss.model.tls.TLSCertificates;

import java.io.Serializable;

/**
 * The data loader which includes server webpage certificates to the response context.
 * Use the method {@code #getCertificates(url)} to extract the data.
 *
 */
public interface TLSCertificateLoader extends Serializable {

    /**
     * The method to extract TLS/SSL-certificates from the given web page
     *
     * @param urlString {@link String} representing a URL of a webpage with a secure connection (HTTPS)
     * @return {@link TLSCertificates} containing the chain of the TLS/SSL certificates and other supportive information
     */
    TLSCertificates getTLSCertificates(final String urlString);

}
