package eu.europa.esig.dss.asic.xades.extension.asics.extender;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;

class ASiCsWithXAdESExtenderBPrettyPrintToLTAPrettyPrintTest extends ASiCsWithXAdESExtenderBToLTATest {

    @Override
    protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
        ASiCWithXAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setPrettyPrint(true);
        return signatureParameters;
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getExtensionParameters() {
        ASiCWithXAdESSignatureParameters extensionParameters = super.getExtensionParameters();
        extensionParameters.setPrettyPrint(true);
        return extensionParameters;
    }

}
