package eu.europa.esig.lote.xml;

import jakarta.xml.bind.JAXBException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class LOTEUtilsTest {

    private static LOTEUtils loteUtils;

    @BeforeAll
    static void init() {
        loteUtils = loteUtils.getInstance();
    }

    @Test
    void getJAXBContext() throws JAXBException {
        assertNotNull(loteUtils.getJAXBContext());
        // cached
        assertNotNull(loteUtils.getJAXBContext());
    }

    @Test
    void getSchema() throws SAXException {
        assertNotNull(loteUtils.getSchema());
        // cached
        assertNotNull(loteUtils.getSchema());
    }

}
