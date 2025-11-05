package eu.europa.esig.lote.xml;

import eu.europa.esig.lote.jaxb.ListOfTrustedEntitiesType;
import jakarta.xml.bind.JAXBException;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import javax.xml.stream.XMLStreamException;
import java.io.File;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class LOTEFacadeTest {

    @Test
    void test() throws JAXBException, XMLStreamException, IOException, SAXException {
        marshallUnmarshall(new File("src/test/resources/valid.xml"));
    }

    private void marshallUnmarshall(File file) throws JAXBException, XMLStreamException, IOException, SAXException {
        LOTEFacade facade = LOTEFacade.newFacade();

        ListOfTrustedEntitiesType loteType = facade.unmarshall(file);
        assertNotNull(loteType);

        loteType = facade.unmarshall(file, false);
        assertNotNull(loteType);

        loteType = facade.unmarshall(file, true);
        assertNotNull(loteType);

        String marshall = facade.marshall(loteType);
        assertNotNull(marshall);

        marshall = facade.marshall(loteType, false);
        assertNotNull(marshall);

        marshall = facade.marshall(loteType, true);
        assertNotNull(marshall);
    }
    
}
