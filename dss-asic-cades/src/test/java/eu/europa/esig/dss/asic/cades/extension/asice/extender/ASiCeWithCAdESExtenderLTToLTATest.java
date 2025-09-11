package eu.europa.esig.dss.asic.cades.extension.asice.extender;

import eu.europa.esig.dss.asic.cades.extension.AbstractTestExtensionWithASiCWithCAdESDocumentExtender;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureProfile;

class ASiCeWithCAdESExtenderLTToLTATest extends AbstractTestExtensionWithASiCWithCAdESDocumentExtender {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_LT;
    }

    @Override
    protected SignatureProfile getTargetSignatureProfile() {
        return SignatureProfile.BASELINE_LTA;
    }

    @Override
    protected ASiCContainerType getContainerType() {
        return ASiCContainerType.ASiC_E;
    }

}
