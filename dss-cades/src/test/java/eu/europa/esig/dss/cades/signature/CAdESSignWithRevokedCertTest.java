/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.validation.CMSDocumentAnalyzer;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzer;
import eu.europa.esig.dss.test.pki.crl.UnknownPkiCRLSource;
import eu.europa.esig.dss.test.pki.ocsp.UnknownPkiOCSPSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESSignWithRevokedCertTest extends AbstractCAdESTestSignature {

    private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
    private CAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private String signingAlias;

    @BeforeEach
    void init() throws Exception {
        documentToSign = new InMemoryDocument("Hello World".getBytes());
        service = new CAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    private void initSignatureParameters() {
        signatureParameters = new CAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
    }


    @Test
    void signBRevokedAndSignBGoodUserTest() {
        signingAlias = REVOKED_USER;
        initSignatureParameters();
        documentToSign = sign();

        signingAlias = GOOD_USER;
        initSignatureParameters();

        DSSDocument doubleSigned = sign();
        assertNotNull(doubleSigned);

        DocumentAnalyzer documentAnalyzer = new CMSDocumentAnalyzer(doubleSigned);
        assertEquals(2, documentAnalyzer.getSignatures().size());
    }

    @Test
    void signBRevokedAndSignLTGoodUserTest() {
        signingAlias = REVOKED_USER;
        initSignatureParameters();
        documentToSign = sign();

        signingAlias = GOOD_USER;
        initSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);

        DSSDocument doubleSigned = sign();
        assertNotNull(doubleSigned);

        DocumentAnalyzer documentAnalyzer = new CMSDocumentAnalyzer(doubleSigned);
        assertEquals(2, documentAnalyzer.getSignatures().size());
    }

    @Test
    void signBGoodUserAndSignBRevokedTest() {
        signingAlias = GOOD_USER;
        initSignatureParameters();
        documentToSign = sign();

        signingAlias = REVOKED_USER;
        initSignatureParameters();

        DSSDocument doubleSigned = sign();
        assertNotNull(doubleSigned);

        DocumentAnalyzer documentAnalyzer = new CMSDocumentAnalyzer(doubleSigned);
        assertEquals(2, documentAnalyzer.getSignatures().size());
    }

    @Test
    void signBGoodUserAndSignLTRevokedTest() {
        signingAlias = GOOD_USER;
        initSignatureParameters();
        documentToSign = sign();

        signingAlias = REVOKED_USER;
        initSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);

        Exception exception = assertThrows(AlertException.class, () -> sign());
        assertTrue(exception.getMessage().contains("Revoked/Suspended certificate(s) detected."));
    }

    @Test
    void signBWithRevocationCheckEnabledTest() {
        signingAlias = GOOD_USER;
        initSignatureParameters();
        signatureParameters.setCheckCertificateRevocation(true);
        documentToSign = sign();

        signingAlias = REVOKED_USER;
        initSignatureParameters();
        signatureParameters.setCheckCertificateRevocation(true);

        Exception exception = assertThrows(AlertException.class, () -> sign());
        assertTrue(exception.getMessage().contains("Revoked/Suspended certificate(s) detected."));

        signingAlias = GOOD_USER_UNKNOWN;
        initSignatureParameters();
        signatureParameters.setCheckCertificateRevocation(true);
        CertificateVerifier certificateVerifier=super.getCompleteCertificateVerifier();
        certificateVerifier.setCrlSource(new UnknownPkiCRLSource(getCertEntityRepository()));
        certificateVerifier.setOcspSource(new UnknownPkiOCSPSource(getCertEntityRepository()));
        service = new CAdESService(certificateVerifier);
        service.setTspSource(getGoodTsa());
        exception = assertThrows(AlertException.class, () -> sign());
        assertTrue(exception.getMessage().contains("Revoked/Suspended certificate(s) detected."));
    }

    @Override
    public void signAndVerify() {
        // do nothing
    }

    @Override
    protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return signingAlias;
    }

}
