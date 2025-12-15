package eu.europa.esig.lote.xml;

import eu.europa.esig.dss.jaxb.common.AbstractJaxbFacade;
import eu.europa.esig.lote.jaxb.ListOfTrustedEntitiesType;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import org.xml.sax.SAXException;

import javax.xml.validation.Schema;
import java.io.IOException;

public class LOTEFacade extends AbstractJaxbFacade<ListOfTrustedEntitiesType> {

    /** TL utils */
    private static final LOTEUtils LOTE_UTILS = LOTEUtils.getInstance();

    /**
     * Default constructor
     */
    protected LOTEFacade() {
        // empty
    }

    /**
     * Creates a new facade
     *
     * @return {@link LOTEFacade}
     */
    public static LOTEFacade newFacade() {
        return new LOTEFacade();
    }

    @Override
    protected JAXBContext getJAXBContext() throws JAXBException {
        return LOTE_UTILS.getJAXBContext();
    }

    @Override
    protected Schema getSchema() throws IOException, SAXException {
        return LOTE_UTILS.getSchema();
    }

    @Override
    protected JAXBElement<ListOfTrustedEntitiesType> wrap(ListOfTrustedEntitiesType jaxbObject) {
        return LOTEUtils.OBJECT_FACTORY.createListOfTrustedEntities(jaxbObject);
    }

}
