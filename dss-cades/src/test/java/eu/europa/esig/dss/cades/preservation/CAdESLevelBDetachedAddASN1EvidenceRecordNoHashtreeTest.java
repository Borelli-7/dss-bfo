package eu.europa.esig.dss.cades.preservation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESLevelBDetachedAddASN1EvidenceRecordNoHashtreeTest extends AbstractCAdESAddEvidenceRecordTest {

    @Override
    protected DSSDocument getSignatureDocument() {
        return new InMemoryDocument(CAdESLevelBDetachedAddASN1EvidenceRecordTest.class.getResourceAsStream(
                "/validation/evidence-record/C-B-B-detached.p7s"));
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new InMemoryDocument(CAdESLevelBDetachedAddASN1EvidenceRecordTest.class.getResourceAsStream(
                "/validation/evidence-record/evidence-record-C-B-B-detached-no-hashtree.ers"));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.CAdES_BASELINE_B, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected EvidenceRecordIncorporationType getEvidenceRecordIncorporationType() {
        return EvidenceRecordIncorporationType.EXTERNAL_EVIDENCE_RECORD;
    }

    @Test
    @Override
    public void addERAndValidate() {
        Exception exception = assertThrows(IllegalInputException.class, super::addERAndValidate);
        assertTrue(exception.getMessage().contains("The digest covered by the evidence record do not correspond to the digest computed on the signature!"));
    }

    @Override
    public List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new InMemoryDocument(
                CAdESLevelBDetachedAddASN1EvidenceRecordTest.class.getResourceAsStream("/validation/evidence-record/sample.zip")));
    }

}
