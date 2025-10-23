package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicyDigestAlgoAndValue;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class JAdESLevelBWithSigPolicyInvalidDigestAlgoTest extends AbstractJAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/jades-level-b-sig-policy-invalid-digest-algo.json");
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
