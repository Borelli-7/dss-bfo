package eu.europa.esig.dss.validation.qwac;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Contains utility methods for performing QWAC validation process
 *
 */
public class QWACUtils {

    private static final Logger LOG = LoggerFactory.getLogger(QWACUtils.class);

    /** Represents a "Link" response header */
    private static final String HEADER_LINK = "Link";

    /**
     * Default constructor
     */
    private QWACUtils() {
        // empty
    }

    /**
     * Loops over the {@code headers} and returns the tls-certificate-binding URL value from a "Link" header if found.
     * If no matching value found, the method returns NULL.
     *
     * @param headers a map of header name and values
     * @return {@link String} TSL Certificate Binding URL
     */
    public static String getTLSCertificateBindingUrl(Map<String, List<String>> headers) {
        List<String> headerValues = headers.get(HEADER_LINK);
        if (headerValues == null) {
            LOG.debug("No Link header found in the obtained map of headers.");
            return null;
        }

        for (String linkHeaderValue : headerValues) {
            try {
                LinkHeaderParser.LinkHeader linkHeader = new LinkHeaderParser().parse(linkHeaderValue);
                if (linkHeader != null) {
                    LOG.debug("'Link' header value was obtained from with value '{}'", linkHeader.getUrl());
                    return linkHeader.getUrl();
                }

            } catch (Exception e) {
                LOG.debug("An error occurred on processing a 'Link' header value : {}", e.getMessage(), e);
            }

        }
        LOG.debug("No Link header contains a rel value of tls-certificate-binding.");
        return null;
    }

    /**
     * Gets TLS Binding Certificates identified from the binding signature
     *
     * @param signature {@link SignatureWrapper}
     * @param certificates a list of {@link CertificateWrapper} candidates
     * @return
     */
    public static List<CertificateWrapper> getIdentifiedTLSCertificates(SignatureWrapper signature,
                                                                        List<CertificateWrapper> certificates) {
        List<CertificateWrapper> result = new ArrayList<>();
        for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
            if (DigestMatcherType.SIG_D_ENTRY == digestMatcher.getType()
                    && digestMatcher.isDataFound() && digestMatcher.isDataIntact()
                    && Utils.isCollectionNotEmpty(digestMatcher.getDataObjectReferences())) {
                for (String tokenId : digestMatcher.getDataObjectReferences()) {
                    for (CertificateWrapper certificate : certificates) {
                        if (tokenId.equals(certificate.getId())) {
                            result.add(certificate);
                        }
                    }
                }
            }
        }
        return result;
    }

}
