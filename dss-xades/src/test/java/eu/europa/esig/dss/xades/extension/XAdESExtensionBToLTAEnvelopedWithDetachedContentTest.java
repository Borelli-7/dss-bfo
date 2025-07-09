package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.fail;

class XAdESExtensionBToLTAEnvelopedWithDetachedContentTest extends AbstractXAdESTestExtension {

    private final DSSDocument WRONG_DOCUMENT = new InMemoryDocument("Bye world".getBytes(), "evil.txt");

    private final FileDocument ORIGINAL_DOCUMENT = toFileDocument(new FileDocument("src/test/resources/sample.xml"));

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_B;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_LTA;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        XAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setDetachedContents(getDetachedContents());
        return signatureParameters;
    }

    @Override
    protected XAdESSignatureParameters getExtensionParameters() {
        XAdESSignatureParameters extensionParameters = super.getExtensionParameters();
        extensionParameters.setDetachedContents(getDetachedContents());
        return extensionParameters;
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(WRONG_DOCUMENT);
    }

    @Override
    public FileDocument getOriginalDocument() {
        return ORIGINAL_DOCUMENT;
    }

    private FileDocument toFileDocument(DSSDocument document) {
        try {
            File originalDoc = Files.createTempFile("dss-", document.getName()).toFile();
            try (FileOutputStream fos = new FileOutputStream(originalDoc); InputStream is = document.openStream()) {
                Utils.copy(is, fos);
            } catch (IOException e) {
                throw new DSSException("Unable to create the original document", e);
            }
            return new FileDocument(originalDoc);

        } catch (IOException e) {
            fail(e);
            return null;
        }
    }

}
