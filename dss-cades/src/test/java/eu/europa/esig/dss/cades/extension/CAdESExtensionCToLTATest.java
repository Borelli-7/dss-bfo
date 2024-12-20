package eu.europa.esig.dss.cades.extension;

import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.FoundRevocationsProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampHashIndexVersion;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.event.Level;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESExtensionCToLTATest extends AbstractCAdESTestExtension {

    private DSSDocument document;
    private CAdESService service;

    @BeforeEach
    void init() {
        document = new FileDocument("src/test/resources/validation/dss-916/test.txt.signed.qes.attached.p7s");

        CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
        certificateVerifier.setCheckRevocationForUntrustedChains(true);
        certificateVerifier.setAlertOnMissingRevocationData(new LogOnStatusAlert(Level.WARN));
        certificateVerifier.setAlertOnExpiredCertificate(new LogOnStatusAlert(Level.WARN));

        service = new CAdESService(certificateVerifier);
        service.setTspSource(getUsedTSPSourceAtExtensionTime());
    }

    @Override
    protected DSSDocument getSignedDocument(DSSDocument doc) {
        return document;
    }

    @Override
    protected void checkFileExtension(DSSDocument document) {
        // skip
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkFinalLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.CAdES_C, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkCertificateValuesEncapsulation(DiagnosticData diagnosticData) {
        super.checkCertificateValuesEncapsulation(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        FoundCertificatesProxy foundCertificates = signature.foundCertificates();
        // not changed because of CAdES_v2
        assertEquals(3, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.SIGNED_DATA).size());
        assertEquals(3, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
    }

    @Override
    protected void checkRevocationDataEncapsulation(DiagnosticData diagnosticData) {
        super.checkRevocationDataEncapsulation(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        FoundRevocationsProxy foundRevocations = signature.foundRevocations();
        assertEquals(0, foundRevocations.getRelatedRevocationsByOrigin(RevocationOrigin.CMS_SIGNED_DATA).size());
        assertEquals(1, foundRevocations.getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES).size());
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        List<TimestampWrapper> timestamps = diagnosticData.getTimestampList();
        assertTrue(Utils.isCollectionNotEmpty(timestamps));
        int signatureTimestampCounter = 0;
        int archiveTimestampV2Counter = 0;
        int archiveTimestampV3Counter = 0;
        for (TimestampWrapper timestamp : timestamps) {
            if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
                if (ArchiveTimestampType.CAdES_V2 == timestamp.getArchiveTimestampType()) {
                    assertNull(timestamp.getAtsHashIndexVersion());
                    ++archiveTimestampV2Counter;

                } else if (ArchiveTimestampType.CAdES_V3 == timestamp.getArchiveTimestampType()) {
                    assertEquals(ArchiveTimestampHashIndexVersion.ATS_HASH_INDEX_V3, timestamp.getAtsHashIndexVersion());
                    assertTrue(timestamp.isAtsHashIndexValid());
                    assertTrue(Utils.isCollectionEmpty(timestamp.getAtsHashIndexValidationMessages()));

                    assertEquals(1, timestamp.getTimestampedSignedData().size());
                    assertEquals(1, timestamp.getTimestampedSignatures().size());
                    assertEquals(2, timestamp.getTimestampedTimestamps().size());
                    assertEquals(6, timestamp.getTimestampedCertificates().size());
                    // additional revocations are embedded in cades_v2 tst
                    assertEquals(3, timestamp.getTimestampedRevocations().size());
                    assertEquals(1, timestamp.getTimestampedOrphanRevocations().size());

                    ++archiveTimestampV3Counter;
                }

            } else if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestamp.getType())) {
                assertNull(timestamp.getAtsHashIndexVersion());
                signatureTimestampCounter++;
            }
        }
        assertEquals(1, signatureTimestampCounter);
        assertEquals(1, archiveTimestampV2Counter);
        assertEquals(timestamps.size() == 2 ? 0 : 1, archiveTimestampV3Counter);
    }

    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(signature.isSigningCertificateIdentified());
        assertTrue(signature.isSigningCertificateReferencePresent());
        assertFalse(signature.isSigningCertificateReferenceUnique());
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanCertificateObjects()));
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanCertificateReferences()));
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanRevocationObjects()));
        assertFalse(Utils.isCollectionEmpty(diagnosticData.getAllOrphanRevocationReferences()));
    }

    @Override
    protected CAdESService getSignatureServiceToExtend() {
        return service;
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.CAdES_C;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_LTA;
    }

}
