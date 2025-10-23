package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicyDigestAlgoAndValue;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class PAdESLevelBWithPolicyInvalidDigestAlgoTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/pades-level-b-sig-policy-invalid-digest-algo.pdf"));
    }

    @Override
    protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
        super.checkSignaturePolicyIdentifier(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        XmlPolicyDigestAlgoAndValue digestAlgoAndValue = signature.getPolicyDigestAlgoAndValue();
        assertNotNull(digestAlgoAndValue);
        assertNull(digestAlgoAndValue.getDigestMethod());
        assertNull(digestAlgoAndValue.getDigestValue());
        assertFalse(digestAlgoAndValue.isDigestAlgorithmsEqual());
        assertFalse(digestAlgoAndValue.isMatch());
    }

}
