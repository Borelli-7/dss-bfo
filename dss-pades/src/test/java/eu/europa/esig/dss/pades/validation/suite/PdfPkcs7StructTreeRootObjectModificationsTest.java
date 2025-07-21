package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PdfPkcs7StructTreeRootObjectModificationsTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/pdf-structtreeroot-changes.pdf"));
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        super.checkPdfRevision(diagnosticData);

        boolean firstSigFound = false;
        boolean secondSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (Utils.isCollectionNotEmpty(signatureWrapper.getPdfSignatureOrFormFillChanges())) {
                firstSigFound = true;
                assertFalse(Utils.isCollectionEmpty(signatureWrapper.getPdfExtensionChanges()));
                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfAnnotationChanges()));
                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfUndefinedChanges()));

            } else {
                secondSigFound = true;
                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfExtensionChanges()));
                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfAnnotationChanges()));
                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfUndefinedChanges()));
            }
        }
        assertTrue(firstSigFound);
        assertTrue(secondSigFound);
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        // no signing-certificate
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertFalse(signatureWrapper.isSigningCertificateIdentified());
            assertFalse(signatureWrapper.isSigningCertificateReferencePresent());

            CertificateRefWrapper signingCertificateReference = signatureWrapper.getSigningCertificateReference();
            assertNull(signingCertificateReference);
        }
    }

}
