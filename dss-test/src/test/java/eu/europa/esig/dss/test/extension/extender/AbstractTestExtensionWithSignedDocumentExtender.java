package eu.europa.esig.dss.test.extension.extender;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureProfile;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SerializableTimestampParameters;
import eu.europa.esig.dss.extension.SignedDocumentExtender;
import eu.europa.esig.dss.spi.extension.DocumentExtender;
import eu.europa.esig.dss.test.extension.AbstractTestExtension;

public abstract class AbstractTestExtensionWithSignedDocumentExtender<SP extends SerializableSignatureParameters,
        TP extends SerializableTimestampParameters> extends AbstractTestExtension<SP, TP> {

    @Override
    protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
        DocumentExtender documentExtender = getDocumentExtender(signedDocument);
        return documentExtender.extendDocument(getTargetSignatureProfile(), getDetachedContents(), getExtensionParameters());
    }

    protected DocumentExtender getDocumentExtender(DSSDocument signedDocument) {
        DocumentExtender documentExtender = SignedDocumentExtender.fromDocument(signedDocument);
        documentExtender.setCertificateVerifier(getCompleteCertificateVerifier());
        documentExtender.setTspSource(getUsedTSPSourceAtExtensionTime());
        return documentExtender;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.getSignatureLevel(getOriginalSignatureLevel().getSignatureForm(), getTargetSignatureProfile());
    }

    protected abstract SignatureProfile getTargetSignatureProfile();

}
