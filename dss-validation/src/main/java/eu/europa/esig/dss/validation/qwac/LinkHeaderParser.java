package eu.europa.esig.dss.validation.qwac;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * This class is used to parse the "Link" HTTP response header value, according to RFC 8288 requirements.
 *
 */
public class LinkHeaderParser {

    private static final Logger LOG = LoggerFactory.getLogger(LinkHeaderParser.class);

    /** Represents a "rel" (relation type) attribute of the "Link" response header */
    private static final String RELATION_TYPE = "rel";

    /** Represents "tls-certificate-binding" value of "rel" attribute identifying a Link to a TLS/SSL binding signature file */
    private static final String TLS_CERTIFICATE_BINDING = "tls-certificate-binding";

    /**
     * Default constructor
     */
    public LinkHeaderParser() {
        // empty
    }

    /**
     * Parses the "Link" header value
     *
     * @param headerValueStr {@link String} representing the "Link" header value content
     * @return {@link LinkHeader}
     */
    public LinkHeader parse(String headerValueStr) {
        if (headerValueStr == null || headerValueStr.trim().isEmpty()) {
            throw new IllegalArgumentException("Link header cannot be null or empty");
        }

        final LinkHeader linkHeader = new LinkHeader();

        // Trim spaces and ensure we start with "<"
        headerValueStr = headerValueStr.trim();

        // Extract the URL from within the angle brackets
        int urlStart = headerValueStr.indexOf('<');
        if (urlStart != 0) {
            throw new IllegalArgumentException("Link header should start with '<' for the URL");
        }

        int urlEnd = headerValueStr.indexOf('>');
        if (urlEnd == -1) {
            throw new IllegalArgumentException("Invalid Link header format, missing closing '>' for URL");
        }

        // Set the URL
        linkHeader.setUrl(headerValueStr.substring(urlStart + 1, urlEnd).trim());

        // Parse any attributes following the URL
        Map<String, String> attributes = new HashMap<>();
        String attributesPart = headerValueStr.substring(urlEnd + 1).trim();

        if (!attributesPart.isEmpty()) {
            String[] parts = attributesPart.split(";");
            for (String part : parts) {
                part = part.trim();
                if (part.isEmpty()) {
                    continue;
                }

                // Split each part into key and value
                String[] keyValue = part.split("=", 2);
                if (keyValue.length == 2) {
                    String key = keyValue[0].trim();
                    String value = keyValue[1].trim().replaceAll("^\"(.*)\"$", "$1"); // remove quotes around value
                    attributes.put(key, value);
                } else {
                    throw new IllegalArgumentException("Invalid Link header attribute format: " + part);
                }
            }

        } else {
            LOG.debug("No attributes found within a 'Link' response header value.");
        }

        // Set the parsed attributes
        linkHeader.setAttributes(attributes);

        return linkHeader;
    }

    /**
     * Checks whether the "Link" header attributes contain a rel value of tls-certificate-binding
     *
     * @param linkHeader {@link LinkHeader} to check
     * @return TRUE if the "Link" attributes is for TLS Certificate Binding, FALSE otherwise
     */
    private boolean isTLSCertificateBindingRel(LinkHeader linkHeader) {
        return TLS_CERTIFICATE_BINDING.equals(linkHeader.getAttributes().get(RELATION_TYPE));
    }

    /**
     * Represents a parsed value of the "Link" HTTP response header
     *
     */
    public class LinkHeader implements Serializable {

        private static final long serialVersionUID = 5652555158066131132L;

        /** The "Link" URL */
        private String url;

        /** Map of the "Link" header attributes */
        private Map<String, String> attributes;

        /**
         * Default constructor
         */
        protected LinkHeader() {
            // empty
        }

        /**
         * Gets the "Link" header value URL
         *
         * @return {@link String}
         */
        public String getUrl() {
            return url;
        }

        /**
         * Sets the "Link" header value URL
         *
         * @param url {@link String}
         */
        public void setUrl(String url) {
            this.url = url;
        }

        /**
         * Gets a map of "Link" header attributes
         *
         * @return a map of attributes
         */
        public Map<String, String> getAttributes() {
            return attributes;
        }

        /**
         * Sets a map of "Link" header attributes
         *
         * @param attributes a map of attributes
         */
        public void setAttributes(Map<String, String> attributes) {
            this.attributes = attributes;
        }

    }

}
