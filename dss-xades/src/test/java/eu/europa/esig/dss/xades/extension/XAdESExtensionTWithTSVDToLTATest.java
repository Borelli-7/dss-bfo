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

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.ExternalResourcesCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ExternalResourcesOCSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.signature.XAdESService;

class XAdESExtensionTWithTSVDToLTATest extends XAdESExtensionTToLTATest {

    @Override
    protected DSSDocument getSignedDocument(DSSDocument doc) {
        return new FileDocument("src/test/resources/validation/xades-t-with-tsvd.xml");
    }

    @Override
    protected XAdESService getSignatureServiceToExtend() {
        XAdESService service = new XAdESService(getCertificateverifier());
        service.setTspSource(getUsedTSPSourceAtExtensionTime());
        return service;
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator documentValidator = super.getValidator(signedDocument);
        documentValidator.setCertificateVerifier(getCertificateverifier());
        return documentValidator;
    }

    private CertificateVerifier getCertificateverifier() {
        CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
        certificateVerifier.setCrlSource(getCRLSource());
        certificateVerifier.setOcspSource(getOCSPSource());
        certificateVerifier.addTrustedCertSources(getTrustedCommonCertificateSource());
        certificateVerifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());
        return certificateVerifier;
    }

    private CertificateSource getTrustedCommonCertificateSource() {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIID/zCCAuegAwIBAgICA+owDQYJYIZIAWUDBAMOBQAwUjEVMBMGA1UEAwwMc2hhMy1yb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjIxMjI3MTQzNjQyWhcNMjQxMDI3MTQzNjQyWjBSMRUwEwYDVQQDDAxzaGEzLWdvb2QtY2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKprrAv623E9+XbLfDNycDAYVIFgWqcPnMphtYXFN1IkDRaax9X5Tj2l1qM2WzB/IT11xvqrW5syG/yq5G2F626QjpP+POGp/xZUGvSvdSkxxmfBGPOgfV21lGp16SP63YqWqqBUp4lxz3XyUgIozPZw70XJZPJX+4wfFEkp3ps+TOSyVGdHo5yxeGt8+uv8qkCMUFb+WrgLzQ1IIKphhV2JE/sYDHehEut+s0e0Ugg0p/74GGm9IMiJ+Wju4rhRW3ZmYnaOe97aN0MsfozU6luZTLitN/pzbcKqbnBWYOWEm3hwclHA1lwz/GMdtlqLXFW2V15lwAfsYSaV+gCoT48CAwEAAaOB3jCB2zAOBgNVHQ8BAf8EBAMCAQYwRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3RvcnkvY3JsL3NoYTMtcm9vdC1jYS5jcmwwUQYIKwYBBQUHAQEERTBDMEEGCCsGAQUFBzAChjVodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcnQvc2hhMy1yb290LWNhLmNydDAdBgNVHQ4EFgQUU/pFam1XX3iYLCtwuTJ1fUh+PNEwDwYDVR0TAQH/BAUwAwEB/zANBglghkgBZQMEAw4FAAOCAQEAR9PlBDpGVnCha1mbQCF6JQkwiWw8gH+LwJGrYVx2df348+uhbFWAmsERW/DC1RSSZjJMWsuWOiaQ1HT3HsPNG0/lfzvna68cboPZNnq6/cKxouGzMItbGPJs4ITffX00YUL59cR/9+wdGGUC848zvpVjIU/hXyXMJhBBLf73KNme83ww6eT/1LFhWxQhgn8N/cHzmfWiNi0bEqdO5Wkswf6+u4VtA1+XzMpyd87YlMDVySFcMiiXjQLdPYrnoiotCt68sEx7efdfi9CcQPhlhu8hPFlA2LWYk8cImbSpFeuarIxxEnJ7uHclF7tIwqePEt9goV8Jttua6+HPvseFUg=="));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIDYjCCAkqgAwIBAgICA+gwDQYJYIZIAWUDBAMOBQAwUjEVMBMGA1UEAwwMc2hhMy1yb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjIxMTI3MTQzNjQyWhcNMjQxMTI3MTQzNjQyWjBSMRUwEwYDVQQDDAxzaGEzLXJvb3QtY2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM+/rCV6wvysjLxdZbkcutCNq2wRO3Ockt13dNW5lBBBM+rV9MY6dDSflKzx+gRMEjRI7MwxVvKE6100/bPzag00DS9/TzdtHKdMGNFNIbItYxeMyMdzhFn8ESsSj6XBlM348kHTBIUF2CdRQ7WxBbb1SYPCzBC2Z6lcLXlsT3TQmCOLSH5lueU4FaBO7dxQtAk6+ezDj1yTjR8K+RXoK92e/XhUN1mAh4NK7KtRe4Cel3mWtWooagviiz4l8VMWslem+8E+bS0oOnGChK01cRNNPBI9ArwKI6pjeLOOGLj/H5WdmPEipuCzIUYwGqY0MSh3O6DyAzRyc+m/+Hlw0X8CAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTjxRV5mo3as1bPiiTuXNXXRaGIRTAPBgNVHRMBAf8EBTADAQH/MA0GCWCGSAFlAwQDDgUAA4IBAQBZfI9z5z2ZymTFgUCiRck7w7NkQPNbSM98E0EmS6ccHDK6uy6y9wTmCVEXpnqLjHYPKZyx258zLhAKzBImzNkC0XSWYyapd7soo+yni4dP/m5ZCdD3M4X8AjMB4RZrg2MM/Z2/kXzWWL+9E1F4H36wB3LYwFCJGpnyNH3G6r9Bz+XlUFRWH9zw6XAg2dptl78+v5hq55I8P95ANmPcPJJWiTFrbtvSx/wiq6NINQFKT3bfzaXvNe7rKOf6NOTA6Sg0z9WNL3/xnHcyYthvFmPJxoOreWmkPhSNcB+CSh9jlywUzjyTi3C8r088tC7dfj9iShnE6R1C0F1L9c/jkzRN"));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIDVzCCAj+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjIxMTI3MTQzNjUyWhcNMjQxMTI3MTQzNjUyWjBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDdHS6x5S1W1GXXME4avFYws0vGJR9G7l5z6IfXHtBDM+Z2ARKtRhGtPiBcZ/G5AIZxoihkbtdKCBlXo0eDeuks+66z5nBDnPI8YSee6KV5b0k+wcxehyZZPVMKxikBRVRArDpvd45tBPqLvQDJv7flYtjTDaN6603QPPW7lOvQL3er7GRy6qUimnoqqjRm4Cd0r/yuFKXg5Wv5VuEhcEwZYTujl7ZInbKlHjvEabZY4T5ySE/cKg9bkyqlBM4kXW3K21P/94EsGLvq8WA9heCv3kzAneF9vy7RFkbukv8rvbE8lLfi+g2wKRrRFEdTmpuNDiewrPxi9HTkhuLnmDvZAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUmTmx3yNNgRoKSBl1Zzg+pMqrRzQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAn9/W95JSR5AErgaBuXDlpF9ko3xPyUrT/vucSrcyV1OzQVb7xGlKK+3grQ+/QiQDuy9kldepBxjBfX2KjaUxhYodm5HvjXoqHUCqkC2I6/P8dtd4QIWNtgsDAsq8fUmR4vDoV6jJVxH9C3GRys4PNEjmDsG5EcUDoBcgIzOzlJGtcKrsMwedmpUq9Ho/CfXHi4+be+yKykGvmBX8mdT7ZKQTpQ8tyHsuPMWqC17PDV1Oj2UmdMR/RSmWmUU33cntbftVlxowVx9lUn4/DFkfwc+a97AZNSWGeIGpVQCFc3Uynp0EwmVd9I3G2vr5h7L571MFrOF9fnxXYey0wu3LsQ=="));
        return trustedCertificateSource;
    }

    private RevocationSource<CRL> getCRLSource() {
        return new ExternalResourcesCRLSource(new InMemoryDocument(Utils.fromBase64("MIIB3TCBxgIBATANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUXDTIzMTEyNzE0MzY1M1oXDTI0MDUyNzEzMzY0M1owRTAhAgIB9xcNMjMxMDI3MTMzNjUyWjAMMAoGA1UdFQQDCgEBMCACAQYXDTIzMTAyNzEzMzY1MlowDDAKBgNVHRUEAwoBATANBgkqhkiG9w0BAQsFAAOCAQEAvT5b/i0wIVfE0gOruDkEmFn3cuNxDKRytNM6loKaheJ2rDpEWTzaYHCNDwCuU51yrMeh6xArw0XGYk6h24XKRVRPcjeVsALWkzDs2VeoN/LitUiL6xm02NZBtxS/gIu2/mAQ4rkNNAu0w0Dq3h++gPH9PbPdM4JSdizdKBfVXSQdsUxW5xXglkcgqrTey7LP05WGGYrgG/8N3YSXYX05Uv8CJfw5QDB0ScARwRpgx1o/I2mCJiZfnr5jvgGiuFOYP9ruDekLWPmqyweUBfBTbyodLuZ39J4jVcu6UziqU4A9cJz4jP0SEmvnWpoTApPd6sKLK7E4AxEcebdNc/BIvg==")));
    }

    private RevocationSource<OCSP> getOCSPSource() {
        return new ExternalResourcesOCSPSource(new InMemoryDocument(Utils.fromBase64("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")));
    }

}
