package eu.europa.esig.dss.enumerations;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Defines QC Identification Method OID identifiers as defined in the ETSI EN 319 412-5
 * "4.3.5 QCStatement stating the used eIDAS/eIDAS2 Article 24. identification method"
 *
 */
public interface QCIdentMethod extends OidDescription {

    /** Logger */
    Logger LOG = LoggerFactory.getLogger(QCIdentMethod.class);

    /** Defines a description for an unknown method by the current implementation */
    String UNKNOWN_METHOD = "qc-identification-method-unknown";

    /**
     * Returns a {@code QCType} by the given OID, if exists
     *
     * @param oid {@link String} to get {@link QCType} for
     * @return {@link QCType} if exists, NULL otherwise
     */
    static QCIdentMethod fromOid(String oid) {
        for (QCIdentMethod type : QCIdentMethodEnum.values()) {
            if (type.getOid().equals(oid)) {
                return type;
            }
        }

        LOG.debug("Unknown QCIdentMethod : '{}'", oid);
        return new QCIdentMethod() {

            private static final long serialVersionUID = 6089958556390661665L;

            @Override
            public String getDescription() { return UNKNOWN_METHOD; }
            @Override
            public String getOid() { return oid; }

        };
    }

}
