package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.RevocationDataVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelLTSigRevocationFreshnessNextUpdateTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE, 1);

        service = new XAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsaByTime(calendar.getTime()));
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator documentValidator = super.getValidator(signedDocument);

        CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();

        RevocationDataVerifier revocationDataVerifier = RevocationDataVerifier.createDefaultRevocationDataVerifier();
        revocationDataVerifier.setCheckRevocationFreshnessNextUpdate(true);
        certificateVerifier.setRevocationDataVerifier(revocationDataVerifier);

        documentValidator.setCertificateVerifier(certificateVerifier);

        return documentValidator;
    }

    @Override
    protected CertificateVerifier getCompleteCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getCompleteCertificateVerifier();
        certificateVerifier.setAIASource(pkiAIASource());
        certificateVerifier.setCrlSource(pkiCRLSource());
        certificateVerifier.setOcspSource(pkiDelegatedOCSPSource());
        return certificateVerifier;
    }

    @Override
    protected Reports verify(DSSDocument signedDocument) {
        // wait one second for revocation data update
        Calendar nextSecond = Calendar.getInstance();
        nextSecond.add(Calendar.SECOND, 1);
        await().atMost(2, TimeUnit.SECONDS).until(() -> Calendar.getInstance().getTime().compareTo(nextSecond.getTime()) > 0);

        return super.verify(signedDocument);
    }

    @Override
    protected void checkRevocationData(DiagnosticData diagnosticData) {
        super.checkRevocationData(diagnosticData);

        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signatureWrapper);

        CertificateWrapper signingCertificate = signatureWrapper.getSigningCertificate();
        assertNotNull(signingCertificate);

        List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
        assertEquals(2, certificateRevocationData.size());

        boolean inputDocumentRevocationFound = false;
        boolean externalRevocationFound = false;
        for (RevocationWrapper revocationWrapper : certificateRevocationData) {
            if (revocationWrapper.getOrigin().isInternalOrigin()) {
                inputDocumentRevocationFound = true;
            } else {
                externalRevocationFound = true;
            }
        }
        assertTrue(inputDocumentRevocationFound);
        assertTrue(externalRevocationFound);
    }

    @Override
    protected String getSigningAlias() {
        return RSA_SHA3_USER;
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

}