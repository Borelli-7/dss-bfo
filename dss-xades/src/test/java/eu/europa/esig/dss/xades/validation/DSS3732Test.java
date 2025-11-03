package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

public class DSS3732Test extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("C:\\Users\\AleksandrBeliakov\\Downloads\\xmlsiged.xml");
    }

}
