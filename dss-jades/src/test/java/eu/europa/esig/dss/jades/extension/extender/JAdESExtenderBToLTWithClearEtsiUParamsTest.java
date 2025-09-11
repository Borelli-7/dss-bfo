package eu.europa.esig.dss.jades.extension.extender;

import eu.europa.esig.dss.enumerations.SignatureProfile;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JAdESExtenderBToLTWithClearEtsiUParamsTest extends JAdESExtenderBToLTATest {

    private SignatureProfile signatureProfile;

    @Override
    protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
        signatureProfile = SignatureProfile.BASELINE_LTA;
        Exception exception = assertThrows(IllegalInputException.class, () -> super.extendSignature(signedDocument));
        assertEquals("Unable to extend JAdES-LTA level. Clear 'etsiU' incorporation requires a canonicalization method!", exception.getMessage());

        signatureProfile = SignatureProfile.BASELINE_LT;
        return super.extendSignature(signedDocument);
    }

    @Override
    protected JAdESSignatureParameters getExtensionParameters() {
        JAdESSignatureParameters extensionParameters = super.getExtensionParameters();
        extensionParameters.setBase64UrlEncodedEtsiUComponents(false);
        return extensionParameters;
    }

    @Override
    protected SignatureProfile getTargetSignatureProfile() {
        return signatureProfile;
    }

}
