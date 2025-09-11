package eu.europa.esig.dss.pades.extension.suite.extender;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PAdESExtenderBToLTAWithContentsTest extends PAdESExtenderBToLTATest {

    private int contentSize;

    @Override
    protected PAdESSignatureParameters getExtensionParameters() {
        PAdESSignatureParameters extensionParameters = super.getExtensionParameters();
        extensionParameters.getSignatureTimestampParameters().setContentSize(contentSize);
        return extensionParameters;
    }

    @Override
    protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
        contentSize = 2; // too small
        Exception exception = assertThrows(IllegalArgumentException.class, () -> super.extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains("Unable to save a document. Reason : The signature size [2] is too small"));

        contentSize = 18944;
        return super.extendSignature(signedDocument);
    }

}
