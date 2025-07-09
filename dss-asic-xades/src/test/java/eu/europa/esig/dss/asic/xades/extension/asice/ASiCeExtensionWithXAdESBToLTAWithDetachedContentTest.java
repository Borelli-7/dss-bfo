package eu.europa.esig.dss.asic.xades.extension.asice;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.extension.AbstractASiCWithXAdESTestExtension;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.util.Collections;
import java.util.List;

class ASiCeExtensionWithXAdESBToLTAWithDetachedContentTest extends AbstractASiCWithXAdESTestExtension {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_B;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_LTA;
    }

    @Override
    protected ASiCContainerType getContainerType() {
        return ASiCContainerType.ASiC_E;
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
        ASiCWithXAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setDetachedContents(getDetachedContents());
        return signatureParameters;
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getExtensionParameters() {
        ASiCWithXAdESSignatureParameters extensionParameters = super.getExtensionParameters();
        extensionParameters.setDetachedContents(getDetachedContents());
        return extensionParameters;
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        // Fake detached content is provided, see DSS-3636. The value should be ignored, as not used.
        return Collections.singletonList(new InMemoryDocument("Bye world".getBytes(), "evil.txt"));
    }

}
