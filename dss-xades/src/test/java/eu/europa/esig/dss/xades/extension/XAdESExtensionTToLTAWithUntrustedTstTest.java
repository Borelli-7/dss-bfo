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
package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.validation.TrustAnchorVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESExtensionTToLTAWithUntrustedTstTest extends AbstractXAdESTestExtension {

    private CertificateVerifier certificateVerifier;
    private XAdESService service;

    @BeforeEach
    void init() throws Exception {
        certificateVerifier = getCompleteCertificateVerifier();
        service = new XAdESService(certificateVerifier);
        service.setTspSource(getGoodTsa());
    }

    @Override
    protected CertificateVerifier getCompleteCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getCompleteCertificateVerifier();
        certificateVerifier.setRevocationFallback(true);
        certificateVerifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());
        return certificateVerifier;
    }

    @Override
    protected TSPSource getUsedTSPSourceAtSignatureTime() {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(getSigningCert().getNotAfter());
        calendar.add(Calendar.MONTH, -6);
        Date tstTime = calendar.getTime();
        return getKeyStoreTSPSourceByNameAndTime(SELF_SIGNED_TSA, tstTime);
    }

    @Override
    protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
        certificateVerifier.setAlertOnExpiredCertificate(new ExceptionOnStatusAlert());

        TrustAnchorVerifier trustAnchorVerifier = TrustAnchorVerifier.createDefaultTrustAnchorVerifier();
        certificateVerifier.setTrustAnchorVerifier(trustAnchorVerifier);

        trustAnchorVerifier.setAcceptTimestampUntrustedCertificateChains(false);

        Exception exception = assertThrows(AlertException.class, () -> super.extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains(
                "The signing certificate has expired and there is no POE during its validity range"));

        trustAnchorVerifier.setAcceptTimestampUntrustedCertificateChains(true);

        return super.extendSignature(signedDocument);
    }

    @Override
    protected XAdESService getSignatureServiceToExtend() {
        return service;
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_T;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_LTA;
    }

    @Override
    protected String getSigningAlias() {
        return EXPIRED_USER;
    }

}
