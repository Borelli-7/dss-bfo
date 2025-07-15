package eu.europa.esig.dss.cades.preservation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CAdESLevelTAddASN1EvidenceRecordWithoutHashtreeTest extends AbstractCAdESAddEvidenceRecordTest {

    @Override
    protected DSSDocument getSignatureDocument() {
        return new InMemoryDocument(CAdESLevelLTAddASN1EvidenceRecordTest.class.getResourceAsStream(
                "/validation/evidence-record/CAdES-BpT.p7m"));
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new InMemoryDocument(CAdESLevelLTAddASN1EvidenceRecordTest.class.getResourceAsStream(
                "/validation/evidence-record/CAdEs-BpT-without-reducedHashTree.ers"));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.CAdES_BASELINE_T, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected EvidenceRecordIncorporationType getEvidenceRecordIncorporationType() {
        return EvidenceRecordIncorporationType.INTERNAL_EVIDENCE_RECORD;
    }

}
