package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.QWACProfile;

/**
 * Parses the {@code eu.europa.esig.dss.enumerations.QWACProfile}
 *
 */
public class QWACProfileParser {

    /**
     * Default constructor
     */
    private QWACProfileParser() {
        // empty
    }

    /**
     * Parses the value and returns {@code QWACProfile}
     *
     * @param v {@link String} to parse
     * @return {@link QWACProfile}
     */
    public static QWACProfile parse(String v) {
        if (v != null) {
            return QWACProfile.fromReadable(v);
        }
        return null;
    }

    /**
     * Gets a text name of the value
     *
     * @param v {@link QWACProfile}
     * @return {@link String}
     */
    public static String print(QWACProfile v) {
        if (v != null) {
            return v.getReadable();
        }
        return null;
    }

}
