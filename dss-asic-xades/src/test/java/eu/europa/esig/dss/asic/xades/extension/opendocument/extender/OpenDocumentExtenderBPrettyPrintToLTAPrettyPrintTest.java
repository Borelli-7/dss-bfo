package eu.europa.esig.dss.asic.xades.extension.opendocument.extender;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;

class OpenDocumentExtenderBPrettyPrintToLTAPrettyPrintTest extends OpenDocumentExtenderBToLTATest {

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
