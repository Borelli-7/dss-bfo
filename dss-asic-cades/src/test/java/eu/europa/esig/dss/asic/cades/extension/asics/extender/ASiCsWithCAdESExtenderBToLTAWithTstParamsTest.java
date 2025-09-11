package eu.europa.esig.dss.asic.cades.extension.asics.extender;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCsWithCAdESExtenderBToLTAWithTstParamsTest extends ASiCsWithCAdESExtenderBToLTATest {

    private boolean extended;

    @Override
    protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
        DSSDocument extendedSignature = super.extendSignature(signedDocument);
        extended = true;
        return extendedSignature;
    }

    @Override
    protected ASiCWithCAdESSignatureParameters getExtensionParameters() {
        ASiCWithCAdESSignatureParameters extensionParameters = super.getExtensionParameters();
        extensionParameters.getSignatureTimestampParameters().setDigestAlgorithm(DigestAlgorithm.SHA384);
        extensionParameters.getArchiveTimestampParameters().setDigestAlgorithm(DigestAlgorithm.SHA512);
        return extensionParameters;
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        if (extended) {
            assertEquals(2, timestampList.size());

            boolean sigTstFound = false;
            boolean arcTstFound = false;
            for (TimestampWrapper timestampWrapper : timestampList) {
                if (TimestampType.SIGNATURE_TIMESTAMP == timestampWrapper.getType()) {
                    assertEquals(DigestAlgorithm.SHA384, timestampWrapper.getMessageImprint().getDigestMethod());
                    sigTstFound = true;
                } else if (TimestampType.ARCHIVE_TIMESTAMP == timestampWrapper.getType()) {
                    assertEquals(DigestAlgorithm.SHA512, timestampWrapper.getMessageImprint().getDigestMethod());
                    arcTstFound = true;
                }
            }
            assertTrue(sigTstFound);
            assertTrue(arcTstFound);
        } else {
            assertEquals(0, timestampList.size());
        }
    }

}
