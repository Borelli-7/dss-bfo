package eu.europa.esig.dss.jades.signature.qwac;

import eu.europa.esig.dss.enumerations.QWACProfile;

class QWAC2ValidationTest extends AbstractQWACValidationTest {

    @Override
    protected QWACProfile getExpectedQWACProfile() {
        return QWACProfile.TLS_BY_QWAC_2;
    }

    @Override
    protected QWACProfile getExpectedSignatureBindingCertificateQWACProfile() {
        return QWACProfile.QWAC_2;
    }

}
