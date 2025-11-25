package eu.europa.esig.dss.jades.signature.qwac;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.QWACProfile;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.Collections;

class QWAC2ValidationMultipleSigsTest extends AbstractQWACValidationTest {

    @Override
    protected DSSDocument sign() {
        DSSDocument firstSignedDoc = super.sign();
        documentToSign = firstSignedDoc;
        DSSDocument secondSignedDoc = super.sign();
        documentToSign = tlsCertificateDocument;
        return secondSignedDoc;
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        JAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
        signatureParameters.setDetachedContents(Collections.singletonList(tlsCertificateDocument));
        return signatureParameters;
    }

    @Override
    protected boolean tlsBindingSignaturePresent() {
        return false;
    }

    @Override
    protected QWACProfile getExpectedQWACProfile() {
        return QWACProfile.NOT_QWAC;
    }

    @Override
    protected QWACProfile getExpectedSignatureBindingCertificateQWACProfile() {
        return null;
    }

}
