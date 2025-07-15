package eu.europa.esig.dss.cades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESEnvelopingLevelERSWithoutReducedHashTreeTest extends AbstractCAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(CAdESEnvelopingLevelERSWithoutReducedHashTreeTest.class
                .getResourceAsStream("/validation/evidence-record/CAdEs-BpT+ER-without-reducedHashTree.p7m"));
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 2;
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        super.checkEvidenceRecords(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        assertEquals(EvidenceRecordIncorporationType.INTERNAL_EVIDENCE_RECORD, evidenceRecordWrapper.getIncorporationType());

        List<XmlDigestMatcher> erDigestMatchers = evidenceRecordWrapper.getDigestMatchers();
        assertEquals(1, erDigestMatchers.size());

        XmlDigestMatcher erDM = erDigestMatchers.get(0);
        assertEquals(DigestMatcherType.EVIDENCE_RECORD_MASTER_SIGNATURE, erDM.getType());
        assertNotNull(erDM.getDigestMethod());
        assertNotNull(erDM.getDigestValue());
        assertTrue(erDM.isDataFound());
        assertTrue(erDM.isDataIntact());

        List<TimestampWrapper> timestampList = evidenceRecordWrapper.getTimestampList();
        assertEquals(1, timestampList.size());

        TimestampWrapper timestampWrapper = timestampList.get(0);
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertTrue(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertTrue(timestampWrapper.isSignatureValid());
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);

        assertEquals(1, Utils.collectionSize(evidenceRecordWrapper.getCoveredSignatures()));
        assertEquals(2, Utils.collectionSize(evidenceRecordWrapper.getCoveredSignedData()));
        assertEquals(3, Utils.collectionSize(evidenceRecordWrapper.getCoveredCertificates()));
        assertEquals(0, Utils.collectionSize(evidenceRecordWrapper.getCoveredRevocations()));
        assertEquals(1, Utils.collectionSize(evidenceRecordWrapper.getCoveredTimestamps()));
        assertEquals(0, Utils.collectionSize(evidenceRecordWrapper.getCoveredEvidenceRecords()));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.CAdES_BASELINE_T, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

}
