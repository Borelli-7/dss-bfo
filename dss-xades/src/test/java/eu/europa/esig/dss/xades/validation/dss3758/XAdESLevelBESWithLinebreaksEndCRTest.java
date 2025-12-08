package eu.europa.esig.dss.xades.validation.dss3758;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESLevelBESWithLinebreaksEndCRTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument(new File("src/test/resources/validation/dss3758/xades-bes-issuer-linebreaks-end-cr.xml"));
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        super.checkSigningCertificateValue(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        CertificateRefWrapper signingCertificateReference = signature.getSigningCertificateReference();
        assertNotNull(signingCertificateReference);
        assertTrue(signature.isSigningCertificateIdentified());
        assertTrue(signingCertificateReference.isIssuerSerialPresent());
        assertTrue(signingCertificateReference.isIssuerSerialMatch());
        assertTrue(signingCertificateReference.isDigestValuePresent());
        assertTrue(signingCertificateReference.isDigestValueMatch());
    }

}
