package eu.europa.esig.dss.cades.extension.extender;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureProfile;

class CAdESExtenderTToLTATest extends AbstractTestExtensionWithCAdESDocumentExtender {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_T;
    }

    @Override
    protected SignatureProfile getTargetSignatureProfile() {
        return SignatureProfile.BASELINE_LTA;
    }

}
