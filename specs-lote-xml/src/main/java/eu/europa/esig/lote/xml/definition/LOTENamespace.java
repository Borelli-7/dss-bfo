package eu.europa.esig.lote.xml.definition;

import eu.europa.esig.dss.xml.common.definition.DSSNamespace;

/**
 * Contains the ETSI TS 119 602 List of Trusted Entities XML namespace definition
 *
 */
public class LOTENamespace {

    /** LOTE XML namespace definition */
    public static final DSSNamespace NS = new DSSNamespace("http://uri.etsi.org/019602/v1#", "lote");

    /**
     * Default constructor
     */
    private LOTENamespace() {
        // empty
    }

}
