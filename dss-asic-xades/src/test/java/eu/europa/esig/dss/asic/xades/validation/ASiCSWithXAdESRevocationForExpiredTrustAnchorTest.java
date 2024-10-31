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
package eu.europa.esig.dss.asic.xades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.tsl.CertificateTrustTime;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ASiCSWithXAdESRevocationForExpiredTrustAnchorTest extends AbstractASiCWithXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/asic-xades-revoc-for-expired-trust-anchor.asics");
    }

    @Override
    protected CertificateSource getTrustedCertificateSource() {
        TrustedListsCertificateSource trustedCertificateSource = new TrustedListsCertificateSource();
        Map<CertificateToken, List<CertificateTrustTime>> trustTimeMap = new HashMap<>();
        trustTimeMap.put(DSSUtils.loadCertificateFromBase64EncodedString("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"),
                Collections.singletonList(new CertificateTrustTime(DSSUtils.parseRFCDate("2010-12-17T10:19:34Z"), null)));
        trustTimeMap.put(DSSUtils.loadCertificateFromBase64EncodedString("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"),
                Collections.singletonList(new CertificateTrustTime(DSSUtils.parseRFCDate("2014-01-28T09:50:20Z"), DSSUtils.parseRFCDate("2016-06-30T22:00:00Z"))));
        trustTimeMap.put(DSSUtils.loadCertificateFromBase64EncodedString("MIIFFDCCA/ygAwIBAgIMc8dpmEmq/3lGUgoKMA0GCSqGSIb3DQEBCwUAMIGCMQswCQYDVQQGEwJIVTERMA8GA1UEBwwIQnVkYXBlc3QxFjAUBgNVBAoMDU1pY3Jvc2VjIEx0ZC4xJzAlBgNVBAMMHk1pY3Jvc2VjIGUtU3ppZ25vIFJvb3QgQ0EgMjAwOTEfMB0GCSqGSIb3DQEJARYQaW5mb0BlLXN6aWduby5odTAeFw0xNjAyMDcxODAwMDBaFw0yODAyMDcxODAwMDBaMIGCMQswCQYDVQQGEwJIVTERMA8GA1UEBwwIQnVkYXBlc3QxFjAUBgNVBAoMDU1pY3Jvc2VjIEx0ZC4xJzAlBgNVBAMMHlF1YWxpZmllZCBlLVN6aWdubyBUU0EgMjAxNiAwMTEfMB0GCSqGSIb3DQEJARYQaW5mb0BlLXN6aWduby5odTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM7MSYAqAlPhWp0Z2yi3GNBc+sosPld48uhRrj/VIRaZXa4m7+ePCiwJamBICyfFWOGHrj6CbFHbuP9GcF87NLRQ5qB5CPLrHkCaJWkAwpUmY9M4bELKJ3m5gOCiwK/JogBA8dFhlY+XiwF6dNpkrrMZlqgDHyyaoXRLiPkDuQ95pkyLG2lOP/zAuJQ1YXoUOlx+yQRuhw/Qlvq4DV81lsfFz55IrRcY2FSrrwp6o9kDz1VCVGCglCpn+OXO+56xK8SCEkwv1tQSwJppebm0c6swiFjCRv/rOoYJEMLcXAlSL2AiE0VEi3kgOtfQPWmwU4mnIvGlwyXH6V+F6ePiQYsCAwEAAaOCAYYwggGCMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgbAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMEUGA1UdIAQ+MDwwOgYOKwYBBAGBqBgCAQEzAQAwKDAmBggrBgEFBQcCARYaaHR0cDovL2NwLmUtc3ppZ25vLmh1L3FjcHMwHQYDVR0OBBYEFJXRTvVDOLmrNMxoijpqpj1I9op7MB8GA1UdIwQYMBaAFMsPxt9CQ8w9y7VII6EaeqYquzRoMBsGA1UdEQQUMBKBEGluZm9AZS1zemlnbm8uaHUwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5lLXN6aWduby5odS9yb290Y2EyMDA5LmNybDBuBggrBgEFBQcBAQRiMGAwKwYIKwYBBQUHMAGGH2h0dHA6Ly9yb290b2NzcDIwMDkuZS1zemlnbm8uaHUwMQYIKwYBBQUHMAKGJWh0dHA6Ly93d3cuZS1zemlnbm8uaHUvcm9vdGNhMjAwOS5jcnQwDQYJKoZIhvcNAQELBQADggEBAKsan0coVmHfwr+U63aLW51XcJ9a3jTuoNGLN144qeI4Rm0iHakrFDqxuZ47fQZOHYdQ0UuvSk9aMcGMKTIe5CzchpAZxfp+3qD8oPJnMJnJTreu3VYHV68GijSX47NAIvJiwpZQsnYlPH3haCyBj3EAaojYAh4ikFrWYGRSn5OKrRVNOOcwkwfFk34MTH0ATmIDnWHY+g21Q6j8z5p8rYL41jSosCv+cOzETjEhUYLanmDJC8Kwyd8w4UjhSfMw7kT/guu4H71cBGcGprb4DF2tJ58RTUtNC42AcOIQhz2NVG+qGOHtqHbshGUFt2QLPcoEOZKuowcTXmsYks8dzUQ="),
                Collections.singletonList(new CertificateTrustTime(DSSUtils.parseRFCDate("2016-02-07T18:00:00Z"), null)));
        trustTimeMap.put(DSSUtils.loadCertificateFromBase64EncodedString("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"),
                Collections.singletonList(new CertificateTrustTime(DSSUtils.parseRFCDate("2014-01-22T09:24:19Z"), null)));
        trustedCertificateSource.setTrustTimeByCertificates(trustTimeMap);
        return trustedCertificateSource;
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        assertEquals(4, diagnosticData.getAllOrphanCertificateObjects().size());
        assertEquals(0, diagnosticData.getAllOrphanCertificateReferences().size());
        assertEquals(4, diagnosticData.getAllOrphanRevocationObjects().size());
        assertEquals(0, diagnosticData.getAllOrphanRevocationReferences().size());
    }

}
