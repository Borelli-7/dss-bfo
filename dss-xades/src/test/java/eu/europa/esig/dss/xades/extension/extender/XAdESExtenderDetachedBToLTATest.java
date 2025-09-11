package eu.europa.esig.dss.xades.extension.extender;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SignatureProfile;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.extension.DocumentExtender;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESExtenderDetachedBToLTATest extends AbstractTestExtensionWithXAdESDocumentExtender {

    private FileDocument originalDocument;

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_B;
    }

    @Override
    protected SignatureProfile getTargetSignatureProfile() {
        return SignatureProfile.BASELINE_LTA;
    }

    @Override
    protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
        DocumentExtender documentExtender = getDocumentExtender(signedDocument);

        Exception exception = assertThrows(AlertException.class, () -> documentExtender.extendDocument(getTargetSignatureProfile()));
        assertTrue(exception.getMessage().contains("Error on signature augmentation"));

        DSSDocument extendedDocument = documentExtender.extendDocument(getTargetSignatureProfile(), getDetachedContents());
        onDocumentExtended(extendedDocument);
        Reports reports = verify(extendedDocument);
        checkFinalLevel(reports.getDiagnosticData());

        extendedDocument = documentExtender.extendDocument(getTargetSignatureProfile(), getDetachedContents(), getExtensionParameters());
        onDocumentExtended(extendedDocument);
        reports = verify(extendedDocument);
        checkFinalLevel(reports.getDiagnosticData());

        // no detached contents
        exception = assertThrows(AlertException.class, () -> documentExtender.extendDocument(getTargetSignatureProfile(), getExtensionParameters()));
        assertTrue(exception.getMessage().contains("Error on signature augmentation"));

        XAdESSignatureParameters extensionParameters = super.getExtensionParameters();
        extensionParameters.setDetachedContents(getDetachedContents());
        extendedDocument = documentExtender.extendDocument(getTargetSignatureProfile(), extensionParameters);
        onDocumentExtended(extendedDocument);
        reports = verify(extendedDocument);
        checkFinalLevel(reports.getDiagnosticData());

        return extendedDocument;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        XAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        return signatureParameters;
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(getOriginalDocument());
    }

    @Override
    public FileDocument getOriginalDocument() {
        if (originalDocument == null) {
            originalDocument = super.getOriginalDocument();
        }
        return originalDocument;
    }

}
