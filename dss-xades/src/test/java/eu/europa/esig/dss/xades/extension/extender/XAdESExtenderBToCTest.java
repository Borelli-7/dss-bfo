package eu.europa.esig.dss.xades.extension.extender;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureProfile;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;

import java.util.List;

class XAdESExtenderBToCTest extends AbstractTestExtensionWithXAdESDocumentExtender {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_B;
    }

    @Override
    protected SignatureProfile getTargetSignatureProfile() {
        return SignatureProfile.EXTENDED_C;
    }

    @Override
    protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
        super.verifySourcesAndDiagnosticDataWithOrphans(advancedSignatures, diagnosticData);
    }

}
