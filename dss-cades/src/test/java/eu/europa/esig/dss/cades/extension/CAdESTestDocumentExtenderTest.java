package eu.europa.esig.dss.cades.extension;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.AbstractSerializableSignatureParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.extension.DocumentExtender;
import eu.europa.esig.dss.test.extension.AbstractTestDocumentExtender;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESTestDocumentExtenderTest extends AbstractTestDocumentExtender {

    private static final String PATH = "/validation/dss-768/FD1&FD2&FEA.pdf.p7m";

    private static final FileDocument FILE_DOCUMENT;

    static {
        File originalDoc = new File("target/FD1&FD2&FEA.pdf.p7m");
        try (FileOutputStream fos = new FileOutputStream(originalDoc); InputStream is = CAdESTestDocumentExtenderTest.class.getResourceAsStream(PATH)) {
            Utils.copy(is, fos);
        } catch (IOException e) {
            throw new DSSException("Unable to create the original document", e);
        }
        FILE_DOCUMENT = new FileDocument(originalDoc);
    }

    @Test
    void isSupported() {
        CAdESDocumentExtender extender = new CAdESDocumentExtender();

        assertTrue(extender.isSupported(FILE_DOCUMENT));
        assertTrue(extender.isSupported(new InMemoryDocument(FILE_DOCUMENT.openStream())));
        assertTrue(extender.isSupported(new InMemoryDocument(new byte[] { 0x30, '1', '2', '3', '4', '5' })));

        assertFalse(extender.isSupported(new InMemoryDocument(new byte[] { '<', '?', 'x', 'm', 'l' })));
        assertFalse(extender.isSupported(new InMemoryDocument(new byte[] { -17, -69, -65, '<' })));
        assertFalse(extender.isSupported(new InMemoryDocument(new byte[] { '<', 'd', 's', ':' })));
    }

    @Override
    protected DocumentExtender initEmptyExtender() {
        return new CAdESDocumentExtender();
    }

    @Override
    protected DocumentExtender initExtender(DSSDocument document) {
        return new CAdESDocumentExtender(document);
    }

    @Override
    protected List<DSSDocument> getValidDocuments() {
        List<DSSDocument> documents = new ArrayList<>();
        documents.add(FILE_DOCUMENT);
        documents.add(new InMemoryDocument(CAdESTestDocumentExtenderTest.class.getResourceAsStream("/validation/CAdESDoubleLTA.p7m")));
        documents.add(new InMemoryDocument(CAdESTestDocumentExtenderTest.class.getResourceAsStream("/validation/counterSig.p7m")));
        return documents;
    }

    @Override
    protected DSSDocument getMalformedDocument() {
        return new InMemoryDocument(CAdESTestDocumentExtenderTest.class.getResourceAsStream("/validation/malformed-cades.p7m"));
    }

    @Override
    protected DSSDocument getOtherTypeDocument() {
        return new InMemoryDocument(CAdESTestDocumentExtenderTest.class.getResourceAsStream("/validation/dss-916/test.txt"));
    }

    @Override
    protected DSSDocument getSignatureDocument() {
        CAdESService service = new CAdESService(getCompleteCertificateVerifier());
        CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

        DSSDocument toSignDocument = getNoSignatureDocument();
        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        return service.signDocument(toSignDocument, signatureParameters, signatureValue);
    }

    @Override
    protected DSSDocument getNoSignatureDocument() {
        return new InMemoryDocument(new byte[] { 0x30, '1', '2', '3', '4', '5' });
    }

    @Override
    protected DSSDocument getXmlEvidenceRecordDocument() {
        return new InMemoryDocument(CAdESTestDocumentExtenderTest.class.getResourceAsStream("/validation/evidence-record/evidence-record-d233a2d9-a257-40dc-bcdb-bf4516b6d1da.xml"));
    }

    @Override
    protected SignatureForm getSignatureForm() {
        return SignatureForm.CAdES;
    }

    @Override
    protected AbstractSerializableSignatureParameters<?> initExtensionParameters() {
        return new CAdESSignatureParameters();
    }

    @Override
    protected DocumentSignatureService<?, ?> initService() {
        return new CAdESService(getCompleteCertificateVerifier());
    }

    @Override
    protected String parseErrorMessage() {
        return "Not a valid CAdES file";
    }

    @Override
    protected String noSignatureErrorMessage() {
        return "Not a valid CAdES file.";
    }

}
