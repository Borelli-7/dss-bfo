package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.JWSSerializationType;

/**
 * Parses the {@code eu.europa.esig.dss.enumerations.JWSSerializationType}
 *
 */
public class JWSSerializationTypeParser {

    /**
     * Default constructor
     */
    private JWSSerializationTypeParser() {
        // empty
    }

    /**
     * Parses the value and returns {@code JWSSerializationType}
     *
     * @param v {@link String} to parse
     * @return {@link JWSSerializationType}
     */
    public static JWSSerializationType parse(String v) {
        if (v != null) {
            return JWSSerializationType.valueOf(v);
        }
        return null;
    }

    /**
     * Gets a text name of the value
     *
     * @param v {@link JWSSerializationType}
     * @return {@link String}
     */
    public static String print(JWSSerializationType v) {
        if (v != null) {
            return v.name();
        }
        return null;
    }

}
