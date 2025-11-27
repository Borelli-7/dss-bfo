package eu.europa.esig.dss.xades.validation.dss3732;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;

class XAdESLevelLTA132EnvelopingTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument(new File("src/test/resources/validation/dss3732/xades-enveloping-arcTst132.xml"));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        super.checkSignatureLevel(diagnosticData);
        assertEquals(SignatureLevel.XAdES_BASELINE_LTA, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

}
