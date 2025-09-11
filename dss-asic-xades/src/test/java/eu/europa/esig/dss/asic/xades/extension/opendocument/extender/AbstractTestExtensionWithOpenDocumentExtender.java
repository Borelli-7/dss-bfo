package eu.europa.esig.dss.asic.xades.extension.opendocument.extender;

import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.extension.extender.AbstractTestExtensionWithSignedDocumentExtender;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractTestExtensionWithOpenDocumentExtender extends AbstractTestExtensionWithSignedDocumentExtender<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> {

    protected FileDocument fileToTest;

    private static Stream<Arguments> data() {
        File folder = new File("src/test/resources/opendocument");
        Collection<File> listFiles = Utils.listFiles(folder,
                new String[] { "odt", "ods", "odp", "odg" }, true);

        List<Arguments> args = new ArrayList<>();
        for (File file : listFiles) {
            args.add(Arguments.of(new FileDocument(file)));
        }
        return args.stream();
    }

    @ParameterizedTest(name = "Validation {index} : {0}")
    @MethodSource("data")
    public void init(FileDocument fileToTest) throws Exception {
        this.fileToTest = fileToTest;

        super.extendAndVerify();
    }

    @Override
    protected FileDocument getOriginalDocument() {
        return fileToTest;
    }

    @Override
    public void extendAndVerify() throws Exception {
    }

    @Override
    protected DSSDocument getSignedDocument(DSSDocument doc) {
        // Sign
        ASiCWithXAdESSignatureParameters signatureParameters = getSignatureParameters();
        ASiCWithXAdESService service = getSignatureServiceToSign();

        ToBeSigned dataToSign = service.getDataToSign(doc, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
                getPrivateKeyEntry());
        return service.signDocument(doc, signatureParameters, signatureValue);
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
        ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(getOriginalSignatureLevel());
        signatureParameters.aSiC().setContainerType(getContainerType());
        return signatureParameters;
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getExtensionParameters() {
        ASiCWithXAdESSignatureParameters extensionParameters = new ASiCWithXAdESSignatureParameters();
        extensionParameters.setSignatureLevel(getFinalSignatureLevel());
        extensionParameters.aSiC().setContainerType(getContainerType());
        return extensionParameters;
    }

    protected abstract ASiCContainerType getContainerType();

    @Override
    protected void compare(DSSDocument signedDocument, DSSDocument extendedDocument) {
        // We check that all original files are present in the extended archive.
        // (signature are not renamed,...)

        List<String> filenames = ZipUtils.getInstance().extractEntryNames(signedDocument);
        List<String> extendedFilenames = ZipUtils.getInstance().extractEntryNames(extendedDocument);

        for (String name : extendedFilenames) {
            assertTrue(filenames.contains(name));
        }

        for (String name : filenames) {
            assertTrue(extendedFilenames.contains(name));
        }
    }

    @Override
    protected void deleteOriginalFile(FileDocument originalDocument) {
        //Skip step
    }

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        assertNotNull(diagnosticData.getContainerInfo());
        assertNotNull(diagnosticData.getContainerType());
        assertNotNull(diagnosticData.getMimetypeFileContent());
        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getContentFiles()));
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        List<String> signatureIdList = diagnosticData.getSignatureIdList();
        for (String signatureId : signatureIdList) {
            SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(signatureId);
            if (diagnosticData.isBLevelTechnicallyValid(signatureId) && !signatureWrapper.isCounterSignature()) {
                List<DSSDocument> retrievedOriginalDocuments = validator.getOriginalDocuments(signatureId);
                assertTrue(Utils.isCollectionNotEmpty(retrievedOriginalDocuments));
                for (DSSDocument document : retrievedOriginalDocuments) {
                    assertNotNull(document);
                }
            }
        }
    }

    @Override
    protected ASiCWithXAdESService getSignatureServiceToSign() {
        ASiCWithXAdESService service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getUsedTSPSourceAtSignatureTime());
        return service;
    }

    @Override
    protected ASiCWithXAdESService getSignatureServiceToExtend() {
        ASiCWithXAdESService service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getUsedTSPSourceAtExtensionTime());
        return service;
    }

}
