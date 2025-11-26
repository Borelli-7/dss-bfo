package eu.europa.esig.dss.jades.signature.qwac;

import eu.europa.esig.dss.enumerations.QWACProfile;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

class QWAC2ValidationJsonNoSigTest extends AbstractQWACValidationTest {

    @Override
    protected DSSDocument sign() {
        return new FileDocument("src/test/resources/sample.json");
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
