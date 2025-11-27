package eu.europa.esig.dss.xades.validation.dss3732;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESLevelLTA132EnvelopingAdditionalObjectTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument(new File("src/test/resources/validation/dss3732/xades-enveloping-arcTst132-add-object.xml"));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XAdES_BASELINE_LTA, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
        assertFalse(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        int sigTstCounter = 0;
        int arcTstCounter = 0;
        for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
            if (TimestampType.SIGNATURE_TIMESTAMP == timestamp.getType()) {
                assertTrue(timestamp.isMessageImprintDataFound());
                assertTrue(timestamp.isMessageImprintDataIntact());
                assertTrue(timestamp.isSignatureIntact());
                assertTrue(timestamp.isSignatureValid());
                ++sigTstCounter;

            } else if (TimestampType.ARCHIVE_TIMESTAMP == timestamp.getType()) {
                assertTrue(timestamp.isMessageImprintDataFound());
                assertFalse(timestamp.isMessageImprintDataIntact());
                assertTrue(timestamp.isSignatureIntact());
                assertFalse(timestamp.isSignatureValid());
                ++arcTstCounter;
            }
        }
        assertEquals(1, sigTstCounter);
        assertEquals(1, arcTstCounter);
    }

}
