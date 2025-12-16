package eu.europa.esig.dss.enumerations;

import java.util.Objects;

/**
 * Contains QcQSCDlegislation statements defined within in the ETSI EN 319 412-5
 *  * "4.3.5 QCStatement stating the used eIDAS/eIDAS2 Article 24. identification method"
 */
public enum QCIdentMethodEnum implements QCIdentMethod {

    /**
     * id-etsi-qct-eIDAS2-acd OBJECT IDENTIFIER ::= { id-etsi-qcs-QcIdentMethod 3 }
     * -- Identification according to eIDAS2 [i.13] Article 24. paragraph 1a a) or c) or d)
     */
    QCT_EIDAS2_ACD("qc-ident-method-eIDAS2-acd", "0.4.0.1862.1.8.3"),

    /**
     * id-etsi-qct-eIDAS2-b OBJECT IDENTIFIER ::= { id-etsi-qcs-QcIdentMethod 4 }
     * -- Identification according to eIDAS2 Article 24. paragraph 1a b)
     */
    QCT_EIDAS2_B("qc-ident-method-eIDAS2-acd", "0.4.0.1862.1.8.4");

    /** The QCIdentMethod description */
    private final String description;

    /** The QCIdentMethod OID */
    private final String oid;

    /**
     * Default constructor
     *
     * @param description {@link String}
     * @param oid {@link String}
     */
    QCIdentMethodEnum(String description, String oid) {
        this.description = description;
        this.oid = oid;
    }

    @Override
    public String getOid() {
        return oid;
    }

    @Override
    public String getDescription() {
        return description;
    }

    /**
     * Gets a QCIdentMethod for the given label description string
     *
     * @param description {@link String}
     * @return {@link QCStatement}
     */
    public static QCIdentMethodEnum forLabel(String description) {
        Objects.requireNonNull(description, "Description label cannot be null!");
        for (QCIdentMethodEnum qcType : values()) {
            if (description.equals(qcType.description)) {
                return qcType;
            }
        }
        return null;
    }
    
}
