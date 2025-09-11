package eu.europa.esig.dss.asic.xades.extension.opendocument.extender;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureProfile;

class OpenDocumentExtenderBToLTATest extends AbstractTestExtensionWithOpenDocumentExtender {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_B;
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
