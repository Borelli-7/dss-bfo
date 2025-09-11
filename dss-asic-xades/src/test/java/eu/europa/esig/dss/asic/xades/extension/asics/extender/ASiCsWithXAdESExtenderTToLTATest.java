package eu.europa.esig.dss.asic.xades.extension.asics.extender;

import eu.europa.esig.dss.asic.xades.extension.AbstractTestExtensionWithASiCWithXAdESDocumentExtender;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureProfile;

class ASiCsWithXAdESExtenderTToLTATest extends AbstractTestExtensionWithASiCWithXAdESDocumentExtender {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_T;
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
