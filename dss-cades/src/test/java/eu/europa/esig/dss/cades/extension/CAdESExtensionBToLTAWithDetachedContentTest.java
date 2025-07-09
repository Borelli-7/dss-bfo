package eu.europa.esig.dss.cades.extension;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.util.Collections;
import java.util.List;

class CAdESExtensionBToLTAWithDetachedContentTest extends AbstractCAdESTestExtension {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_B;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_LTA;
    }

    @Override
    protected CAdESSignatureParameters getSignatureParameters() {
        CAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setDetachedContents(getDetachedContents());
        return signatureParameters;
    }

    @Override
    protected CAdESSignatureParameters getExtensionParameters() {
        CAdESSignatureParameters extensionParameters = super.getExtensionParameters();
        extensionParameters.setDetachedContents(getDetachedContents());
        return extensionParameters;
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        // Fake detached content is provided, see DSS-3636. The value should be ignored, as not used.
        return Collections.singletonList(new InMemoryDocument("Bye world".getBytes(), "evil.txt"));
    }

}
