package eu.europa.esig.dss.jades.extension.extender;

import eu.europa.esig.dss.jades.JAdESSignatureParameters;

class JAdESExtenderTToLTWithClearEtsiUParamsTest extends JAdESExtenderTToLTTest {

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        JAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setBase64UrlEncodedEtsiUComponents(false);
        return signatureParameters;
    }

}
