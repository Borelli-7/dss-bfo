package eu.europa.esig.dss.asic.xades.signature.asice;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.asic.xades.signature.SimpleASiCWithXAdESFilenameFactory;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEXAdESLevelBCustomManifestNameTest extends AbstractASiCEWithXAdESMultipleDocumentsTestSignature {

    private ASiCWithXAdESService service;
    private ASiCWithXAdESSignatureParameters signatureParameters;
    private List<DSSDocument> documentToSigns = new ArrayList<>();

    @BeforeEach
    public void init() throws Exception {
        documentToSigns.add(new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT));
        documentToSigns.add(new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeType.TEXT));
        documentToSigns.add(new InMemoryDocument(DSSUtils.EMPTY_BYTE_ARRAY, "emptyByteArray"));

        signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        SimpleASiCWithXAdESFilenameFactory filenameFactory = new SimpleASiCWithXAdESFilenameFactory();
        filenameFactory.setManifestFilename("xades-manifest.xml");
        getService().setAsicFilenameFactory(filenameFactory);

        Exception exception = assertThrows(IllegalArgumentException.class, () -> super.sign());
        assertEquals("A manifest file within ASiC with XAdES container shall have name 'META-INF/manifest.xml'!",
                exception.getMessage());

        filenameFactory.setManifestFilename("manifest.xml");
        getService().setAsicFilenameFactory(filenameFactory);

        return super.sign();
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        List<DSSDocument> retrievedDocuments = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
        for (DSSDocument document : documentToSigns) {
            boolean found = false;
            for (DSSDocument retrievedDoc : retrievedDocuments) {
                if (Arrays.equals(DSSUtils.toByteArray(document), DSSUtils.toByteArray(retrievedDoc))) {
                    found = true;
                }
            }
            assertTrue(found);
        }
    }

    @Override
    protected ASiCWithXAdESService getService() {
        return service;
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected List<DSSDocument> getDocumentsToSign() {
        return documentToSigns;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
