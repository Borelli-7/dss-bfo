package eu.europa.esig.dss.jades.signature.qwac;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.QWACProfile;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;

import java.util.Collections;

class QWAC2ValidationJsonFlattenedTest extends AbstractQWACValidationTest {

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        JAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);
        signatureParameters.setDetachedContents(Collections.singletonList(tlsCertificateDocument));
        return signatureParameters;
    }

    @Override
    protected QWACProfile getExpectedQWACProfile() {
        return QWACProfile.NOT_QWAC;
    }

    @Override
    protected QWACProfile getExpectedSignatureBindingCertificateQWACProfile() {
        return QWACProfile.QWAC_2;
    }

}
