package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESCounterSignatureNoTypeValidTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/xades-counter-signature-no-type.xml");
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        super.checkBLevelValid(diagnosticData);

        int sigCounter = 0;
        int counterSigCounter = 0;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.isCounterSignature()) {
                assertTrue(signatureWrapper.isBLevelTechnicallyValid());
                assertTrue(signatureWrapper.isSignatureIntact());
                assertTrue(signatureWrapper.isSignatureValid());

                assertEquals(3, signatureWrapper.getDigestMatchers().size());

                int counterSigDMCounter = 0;
                int counterSigSigValueDMCounter = 0;
                int otherRefCounter = 0;
                for (XmlDigestMatcher digestMatcher : signatureWrapper.getDigestMatchers()) {
                    assertTrue(digestMatcher.isDataFound());
                    assertTrue(digestMatcher.isDataIntact());
                    if (DigestMatcherType.COUNTER_SIGNATURE == digestMatcher.getType()) {
                        ++counterSigDMCounter;
                    } else if (DigestMatcherType.COUNTER_SIGNED_SIGNATURE_VALUE == digestMatcher.getType()) {
                        ++counterSigSigValueDMCounter;
                    } else {
                        ++otherRefCounter;
                    }
                }
                assertEquals(1, counterSigDMCounter);
                assertEquals(1, counterSigSigValueDMCounter);
                assertEquals(1, otherRefCounter);

                ++counterSigCounter;
            } else {
                assertTrue(signatureWrapper.isBLevelTechnicallyValid());
                assertTrue(signatureWrapper.isSignatureIntact());
                assertTrue(signatureWrapper.isSignatureValid());

                ++sigCounter;
            }
        }
        assertEquals(1, sigCounter);
        assertEquals(1, counterSigCounter);
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        super.checkSignatureLevel(diagnosticData);

        int sigCounter = 0;
        int counterSigCounter = 0;

        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.isCounterSignature()) {
                assertEquals(SignatureLevel.XAdES_BASELINE_B, signatureWrapper.getSignatureFormat());
                ++counterSigCounter;
            } else {
                assertEquals(SignatureLevel.XAdES_BES, signatureWrapper.getSignatureFormat());
                ++sigCounter;
            }
        }
        assertEquals(1, sigCounter);
        assertEquals(1, counterSigCounter);
    }

}
