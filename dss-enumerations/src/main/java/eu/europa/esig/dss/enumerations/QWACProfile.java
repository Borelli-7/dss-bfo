package eu.europa.esig.dss.enumerations;

/**
 * Contains QWAC profiles as per ETSI TS 119 411-5
 *
 */
public enum QWACProfile {

    /*
     * Qualified certificate for website authentication based on Approach #1 in clause 1 of the ETSI TS 119 411-5
     */
    QWAC_1("1-QWAC"),

    /*
     * Qualified certificate for website authentication based on Approach #2 in clause 1 of the ETSI TS 119 411-5
     */
    QWAC_2("2-QWAC"),

    /*
     * A TLS certificate supported by a qualified certificate for website authentication based on Approach #2
     * in clause 1 of the ETSI TS 119 411-5, through TLS Certificate Binding
     */
    TLS_BY_QWAC_2("TLS certificate supported by 2-QWAC"),

    /*
     * Not a Qualified certificate for website authentication based on clause 1 of the ETSI TS 119 411-5
     */
    NOT_QWAC("Not QWAC");

    /** User-friendly identifier of the QWAC certificate type */
    private final String readable;

    /**
     * Default constructor
     *
     * @param readable {@link String}
     */
    QWACProfile(final String readable) {
        this.readable = readable;
    }

    /**
     * Gets the user-friendly label
     *
     * @return {@link String}
     */
    public String getReadable() {
        return readable;
    }

    /**
     * Gets the {@code QWACProfile} from readbale {@code String}
     *
     * @param readable {@link String}
     * @return {@link QWACProfile}
     */
    public static QWACProfile fromReadable(String readable) {
        if (readable == null) {
            return null;
        }
        for (QWACProfile qwacProfile : values()) {
            if (readable.equals(qwacProfile.getReadable())) {
                return qwacProfile;
            }
        }
        return null;
    }

}
