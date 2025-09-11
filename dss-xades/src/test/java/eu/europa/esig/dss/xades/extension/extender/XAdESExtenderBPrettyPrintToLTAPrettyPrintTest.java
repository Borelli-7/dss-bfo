package eu.europa.esig.dss.xades.extension.extender;

import eu.europa.esig.dss.xades.XAdESSignatureParameters;

class XAdESExtenderBPrettyPrintToLTAPrettyPrintTest extends XAdESExtenderBToLTATest {

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        XAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setPrettyPrint(true);
        return signatureParameters;
    }

    @Override
    protected XAdESSignatureParameters getExtensionParameters() {
        XAdESSignatureParameters extensionParameters = super.getExtensionParameters();
        extensionParameters.setPrettyPrint(true);
        return extensionParameters;
    }

}
