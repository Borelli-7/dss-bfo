package eu.europa.esig.lote.xml;

import eu.europa.esig.dss.jaxb.common.XSDAbstractUtils;
import eu.europa.esig.lote.jaxb.ObjectFactory;
import eu.europa.esig.xmldsig.XmlDSigUtils;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;

import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import java.util.List;

/**
 * ETSI TS 119 602 List of Trusted Entities XML Utils
 *
 */
public class LOTEUtils extends XSDAbstractUtils {

    /** The Object Factory to use */
    public static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();

    public static final String LOTE_SCHEMA_LOCATION = "/xsd/19602_xsd_v0.0.6a.xsd";
    public static final String LOTE_SIE_SCHEMA_LOCATION = "/xsd/19602_xsd_schema_sie_v0.0.6.xsd";
    public static final String LOTE_TIE_SCHEMA_LOCATION = "/xsd/19602_xsd_schema_tie_v0.0.6.xsd";

    /** Singleton */
    private static LOTEUtils singleton;

    /** JAXBContext */
    private JAXBContext jc;

    /**
     * Empty constructor
     */
    private LOTEUtils() {
        // empty
    }

    /**
     * Returns instance of {@code LOTEUtils}
     *
     * @return {@link LOTEUtils}
     */
    public static LOTEUtils getInstance() {
        if (singleton == null) {
            singleton = new LOTEUtils();
        }
        return singleton;
    }

    @Override
    public JAXBContext getJAXBContext() throws JAXBException {
        if (jc == null) {
            jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.xmldsig.jaxb.ObjectFactory.class,
                    eu.europa.esig.lote.jaxb.sie.ObjectFactory.class,
                    eu.europa.esig.lote.jaxb.tie.ObjectFactory.class);
        }
        return jc;
    }

    @Override
    public List<Source> getXSDSources() {
        List<Source> xsdSources = XmlDSigUtils.getInstance().getXSDSources();
        xsdSources.add(new StreamSource(LOTEUtils.class.getResourceAsStream(LOTE_SCHEMA_LOCATION)));
        xsdSources.add(new StreamSource(LOTEUtils.class.getResourceAsStream(LOTE_SIE_SCHEMA_LOCATION)));
        xsdSources.add(new StreamSource(LOTEUtils.class.getResourceAsStream(LOTE_TIE_SCHEMA_LOCATION)));
        return xsdSources;
    }

}
