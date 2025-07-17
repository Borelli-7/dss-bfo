package eu.europa.esig.dss.xades.preservation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.xades.evidencerecord.XAdESEvidenceRecordIncorporationParameters;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class XAdESLevelBAddXMLEvidenceRecordChainRenewalExclusiveCanonicalizationTest extends AbstractXAdESAddEvidenceRecordTest {

    private XAdESEvidenceRecordIncorporationParameters evidenceRecordIncorporationParameters;

    @BeforeEach
    void init() {
        evidenceRecordIncorporationParameters = super.getEvidenceRecordIncorporationParameters();
    }

    @Override
    protected DSSDocument getSignatureDocument() {
        return new FileDocument("src/test/resources/validation/evidence-record/incorporation/XAdES-B.xml");
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidence-record/incorporation/evidence-record-XAdES-B-exclusive.xml");
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XAdES_BASELINE_B, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected EvidenceRecordTypeEnum getEvidenceRecordType() {
        return EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD;
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordTimestamps(diagnosticData);

        EvidenceRecordWrapper evidenceRecordWrapper = diagnosticData.getEvidenceRecords().get(0);
        assertEquals(2, evidenceRecordWrapper.getTimestampList().size());
    }

    @Test
    @Override
    public void addERAndValidate() {
        super.addERAndValidate();

        // The exclusive canonicalization allows embedding of the ER using any namespace
        evidenceRecordIncorporationParameters.setXadesERNamespace(new DSSNamespace("http://uri.etsi.org/19132/v1.1.1#", ""));
        super.addERAndValidate();

        evidenceRecordIncorporationParameters.setXadesERNamespace(new DSSNamespace("http://uri.etsi.org/19132/v1.1.1#", "random"));
        super.addERAndValidate();
    }

    @Override
    protected XAdESEvidenceRecordIncorporationParameters getEvidenceRecordIncorporationParameters() {
        return evidenceRecordIncorporationParameters;
    }

}
