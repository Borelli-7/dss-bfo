package eu.europa.esig.dss.jades.extension.extender;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureProfile;

class JAdESExtenderLTToLTATest extends AbstractTestExtensionWithJAdESDocumentExtender {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.JAdES_BASELINE_LT;
    }

    @Override
    protected SignatureProfile getTargetSignatureProfile() {
        return SignatureProfile.BASELINE_LTA;
    }

}
