package eu.europa.esig.dss.asic.cades.extension.asics.extender;

import eu.europa.esig.dss.asic.cades.extension.AbstractTestExtensionWithASiCWithCAdESDocumentExtender;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureProfile;

class ASiCsWithCAdESExtenderTToLTATest extends AbstractTestExtensionWithASiCWithCAdESDocumentExtender {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_T;
    }

    @Override
    protected SignatureProfile getTargetSignatureProfile() {
        return SignatureProfile.BASELINE_LTA;
    }

    @Override
    protected ASiCContainerType getContainerType() {
        return ASiCContainerType.ASiC_S;
    }

}
