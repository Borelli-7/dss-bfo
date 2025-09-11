package eu.europa.esig.dss.test.extension;

import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureProfile;
import eu.europa.esig.dss.model.AbstractSerializableSignatureParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.extension.DocumentExtender;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractTestDocumentExtender extends PKIFactoryAccess {

    protected abstract DocumentExtender initEmptyExtender();

    protected abstract DocumentExtender initExtender(DSSDocument document);

    protected abstract List<DSSDocument> getValidDocuments();

    protected abstract DSSDocument getMalformedDocument();

    protected abstract DSSDocument getOtherTypeDocument();

    protected abstract DSSDocument getSignatureDocument();

    protected abstract DSSDocument getNoSignatureDocument();

    protected DSSDocument getBinaryDocument() {
        return new InMemoryDocument(new byte[] { '1', '2', '3' });
    }

    protected abstract DSSDocument getXmlEvidenceRecordDocument();

    @Test
    public void extendSignaturesProfileOnly() {
        DSSDocument document = getSignatureDocument();
        DocumentExtender extender = initExtender(document);
        extendAndValidate(extender, getTargetSignatureProfile());
    }

    @Test
    public void extendSignaturesWithExtensionParameters() {
        DSSDocument document = getSignatureDocument();
        DocumentExtender extender = initExtender(document);
        AbstractSerializableSignatureParameters<?> extensionParameters = initExtensionParameters();
        extensionParameters.setSignatureLevel(getFinalSignatureLevel());
        extendAndValidate(extender, getTargetSignatureProfile(), extensionParameters);
    }

    @Test
    public void extendSignaturesDoubleExtensionParams() {
        DSSDocument document = getSignatureDocument();
        DocumentExtender extender = initExtender(document);
        AbstractSerializableSignatureParameters<?> extensionParameters = initExtensionParameters();
        extensionParameters.setSignatureLevel(getFinalSignatureLevel());
        extendAndValidate(extender, getTargetSignatureProfile(), extensionParameters, initExtensionParameters());
    }

    @Test
    public void extendSignaturesWithExtensionParametersNoSignatureLevel() {
        DSSDocument document = getSignatureDocument();
        DocumentExtender extender = initExtender(document);
        extendAndValidate(extender, getTargetSignatureProfile(), initExtensionParameters());
    }

    @Test
    public void extendSignaturesNullProfile() {
        DSSDocument document = getSignatureDocument();
        DocumentExtender extender = initExtender(document);
        Exception exception = assertThrows(NullPointerException.class, () -> extendAndValidate(extender, null));
        assertEquals("SignatureProfile cannot be null!", exception.getMessage());
    }

    @Test
    public void extendSignaturesBProfile() {
        DSSDocument document = getSignatureDocument();
        DocumentExtender extender = initExtender(document);

        Exception exception = assertThrows(UnsupportedOperationException.class, () -> extendAndValidate(extender, SignatureProfile.BASELINE_B));
        SignatureLevel signatureLevel = SignatureLevel.getSignatureLevel(getSignatureForm(), SignatureProfile.BASELINE_B);
        assertEquals(String.format("Unsupported signature format '%s' for extension.", signatureLevel), exception.getMessage());
    }

    @Test
    public void extendSignaturesImpossibleProfile() {
        DSSDocument document = getSignatureDocument();
        DocumentExtender extender = initExtender(document);
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> extendAndValidate(extender, SignatureProfile.NOT_ETSI));
        SignatureLevel signatureLevel = SignatureLevel.getSignatureLevel(getSignatureForm(), SignatureProfile.NOT_ETSI);
        assertEquals(String.format("Unsupported signature format '%s' for extension.", signatureLevel), exception.getMessage());
    }

    @Test
    public void binaryDocumentExtension() {
        DSSDocument document = getBinaryDocument();
        DocumentExtender extender = initExtender(document);
        Exception exception = assertThrows(IllegalInputException.class, () -> extendAndValidate(extender, getTargetSignatureProfile()));
        assertTrue(exception.getMessage().contains(parseErrorMessage()), exception.getMessage());
    }

    @Test
    public void malformedDocumentExtension() {
        DSSDocument document = getMalformedDocument();
        DocumentExtender extender = initExtender(document);
        Exception exception = assertThrows(IllegalInputException.class, () -> extendAndValidate(extender, getTargetSignatureProfile()));
        assertTrue(exception.getMessage().contains(parseErrorMessage()), exception.getMessage());
    }

    @Test
    public void otherDocumentTypeExtension() {
        DSSDocument document = getOtherTypeDocument();
        DocumentExtender extender = initExtender(document);
        Exception exception = assertThrows(IllegalInputException.class, () -> extendAndValidate(extender, getTargetSignatureProfile()));
        assertTrue(exception.getMessage().contains(parseErrorMessage()), exception.getMessage());
    }

    @Test
    public void noSignatureDocumentExtension() {
        DSSDocument document = getNoSignatureDocument();
        DocumentExtender extender = initExtender(document);
        Exception exception = assertThrows(IllegalInputException.class, () -> extendAndValidate(extender, getTargetSignatureProfile()));
        assertTrue(exception.getMessage().contains(noSignatureErrorMessage()), exception.getMessage());
    }

    protected abstract String parseErrorMessage();

    protected abstract String noSignatureErrorMessage();

    @Test
    public void isSupportedValidDocument() {
        List<DSSDocument> documents = getValidDocuments();
        for (DSSDocument document : documents) {
            assertTrue(initEmptyExtender().isSupported(document));
        }
    }

    @Test
    public void isSupportedBinaryDocument() {
        assertFalse(initEmptyExtender().isSupported(getBinaryDocument()));
    }

    @Test
    public void isSupportedMalformedDocument() {
        assertFalse(initEmptyExtender().isSupported(getMalformedDocument()));
    }

    @Test
    public void isSupportedOtherTypeDocument() {
        assertFalse(initEmptyExtender().isSupported(getOtherTypeDocument()));
    }

    @Test
    public void isSupportedNoSignatureDocument() {
        DSSDocument document = getNoSignatureDocument();
        if (document != null) {
            assertTrue(initEmptyExtender().isSupported(document));
        }
    }

    @Test
    public void isSupportedEvidenceRecordDocument() {
        DSSDocument document = getXmlEvidenceRecordDocument();
        if (document != null) {
            assertFalse(initEmptyExtender().isSupported(document));
        }
    }

    @Test
    public void nullDocumentProvided() {
        Exception exception = assertThrows(NullPointerException.class, () -> initExtender(null));
        assertEquals("Document to be extended cannot be null!", exception.getMessage());
    }

    @Test
    public void nullFromDocument() {
        Exception exception = assertThrows(NullPointerException.class, () ->  SignedDocumentValidator.fromDocument(null));
        assertEquals("DSSDocument is null", exception.getMessage());
    }

    protected void extendAndValidate(DocumentExtender extender, SignatureProfile signatureProfile,
                                     SerializableSignatureParameters... signatureParameters) {
        extender.setCertificateVerifier(getCompleteCertificateVerifier());
        extender.setTspSource(getGoodTsa());

        DSSDocument extendedDocument = extender.extendDocument(signatureProfile, signatureParameters);
        validate(extendedDocument);
    }

    protected void validate(DSSDocument extendedDocument) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(extendedDocument);
        validator.setCertificateVerifier(new CommonCertificateVerifier());

        Reports reports = validator.validateDocument();
        assertNotNull(reports);
        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        for (String signatureId : simpleReport.getSignatureIdList()) {
            assertEquals(getFinalSignatureLevel(), simpleReport.getSignatureFormat(signatureId));
        }
    }

    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.getSignatureLevel(getSignatureForm(), getTargetSignatureProfile());
    }

    protected abstract SignatureForm getSignatureForm();

    protected SignatureProfile getTargetSignatureProfile() {
        return SignatureProfile.BASELINE_LTA;
    }

    protected abstract AbstractSerializableSignatureParameters<?> initExtensionParameters();

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
