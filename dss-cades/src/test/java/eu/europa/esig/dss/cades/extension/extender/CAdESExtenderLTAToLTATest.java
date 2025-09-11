package eu.europa.esig.dss.cades.extension.extender;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureProfile;

class CAdESExtenderLTAToLTATest extends AbstractTestExtensionWithCAdESDocumentExtender {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_LTA;
    }

    @Override
    protected SignatureProfile getTargetSignatureProfile() {
        return SignatureProfile.BASELINE_LTA;
    }

}
