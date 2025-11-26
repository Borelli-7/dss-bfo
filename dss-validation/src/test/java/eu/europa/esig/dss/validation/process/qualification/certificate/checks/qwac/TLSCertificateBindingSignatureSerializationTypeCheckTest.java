package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qwac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks.TLSCertificateBindingSignatureSerializationTypeCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TLSCertificateBindingSignatureSerializationTypeCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setJWSSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        TLSCertificateBindingSignatureSerializationTypeCheck tlscbssc = new TLSCertificateBindingSignatureSerializationTypeCheck(
                i18nProvider, result, new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        tlscbssc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidFlattenedTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setJWSSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        TLSCertificateBindingSignatureSerializationTypeCheck tlscbssc = new TLSCertificateBindingSignatureSerializationTypeCheck(
                i18nProvider, result, new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        tlscbssc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidJsonSerializationTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setJWSSerializationType(JWSSerializationType.JSON_SERIALIZATION);

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        TLSCertificateBindingSignatureSerializationTypeCheck tlscbssc = new TLSCertificateBindingSignatureSerializationTypeCheck(
                i18nProvider, result, new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        tlscbssc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void nullTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSignature xmlSignature = new XmlSignature();

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        TLSCertificateBindingSignatureSerializationTypeCheck tlscbssc = new TLSCertificateBindingSignatureSerializationTypeCheck(
                i18nProvider, result, new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        tlscbssc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
