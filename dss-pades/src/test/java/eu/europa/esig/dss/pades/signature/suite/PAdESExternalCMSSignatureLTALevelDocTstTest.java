/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.cades.signature.CMSSignedDocument;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.ExternalCMSService;
import eu.europa.esig.dss.pades.signature.PAdESWithExternalCMSService;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESExternalCMSSignatureLTALevelDocTstTest extends AbstractPAdESTestSignature {

    private PAdESSignatureParameters signatureParameters;
    private Date signingTime;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        signingTime = new Date();
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
    }

    @Override
    protected DSSDocument sign() {
        PAdESWithExternalCMSService service = new PAdESWithExternalCMSService();
        service.setCertificateVerifier(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());

        PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingTime);
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
        signatureParameters.setReason("DSS testing");

        DSSMessageDigest messageDigest = service.getMessageDigest(documentToSign, signatureParameters);
        assertNotNull(messageDigest);

        // Embedded CAdES is generated by a third party
        CMSSignedDocument cmsSignedData = getSignedCMSignedData(messageDigest);
        assertNotNull(cmsSignedData);

        assertTrue(service.isValidCMSSignedData(messageDigest, cmsSignedData));
        assertTrue(service.isValidPAdESBaselineCMSSignedData(messageDigest, cmsSignedData));

        return service.signDocument(documentToSign, signatureParameters, cmsSignedData);
    }

    /**
     * Computes a CAdES with specific things for PAdES
     */
    private CMSSignedDocument getSignedCMSignedData(DSSMessageDigest messageDigest) {
        ExternalCMSService padesCMSGeneratorService = new ExternalCMSService(getOfflineCertificateVerifier());
        padesCMSGeneratorService.setTspSource(getGoodTsa());

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingTime);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.setReason("DSS testing");

        ToBeSigned dataToSign = padesCMSGeneratorService.getDataToSign(messageDigest, signatureParameters);

        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());

        CMSSignedDocument cmsSignedDocument = padesCMSGeneratorService.signMessageDigest(messageDigest, signatureParameters, signatureValue);

        // expected signature level
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

        return cmsSignedDocument;
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<TimestampWrapper> timestampList = signature.getTimestampList();
        assertEquals(2, timestampList.size());
        assertEquals(2, signature.getTLevelTimestamps().size());
        assertEquals(1, signature.getALevelTimestamps().size());

        int docTstCounter = 0;
        for (TimestampWrapper timestampWrapper : timestampList) {
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            if (TimestampType.DOCUMENT_TIMESTAMP.equals(timestampWrapper.getType())) {
                ++docTstCounter;
            }
        }
        assertEquals(2, docTstCounter);
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        super.checkSignatureLevel(diagnosticData);
        assertEquals(SignatureLevel.PAdES_BASELINE_LTA, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> getService() {
        return null;
    }

    @Override
    protected PAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
