package eu.europa.esig.dss.jades.signature.qwac;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.QWACProfile;
import eu.europa.esig.dss.enumerations.SubIndication;

class QWAC2ValidationTlsBindingSignatureNotTrustedTest extends AbstractQWACValidationTest {

    @Override
    protected QWACProfile getExpectedQWACProfile() {
        return QWACProfile.NOT_QWAC;
    }

    @Override
    protected QWACProfile getExpectedSignatureBindingCertificateQWACProfile() {
        return QWACProfile.NOT_QWAC;
    }

    @Override
    protected String getSigningAlias() {
        return SELF_SIGNED_USER;
    }

    @Override
    protected Indication getExpectedTLSBindingSignatureIndication() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getExpectedTLSBindingSignatureSubIndication() {
        return SubIndication.NO_CERTIFICATE_CHAIN_FOUND;
    }

}
