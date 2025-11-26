package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qwac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks.TLSCertificateBindingSignatureFormatCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TLSCertificateBindingSignatureFormatCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setSignatureFormat(SignatureLevel.JAdES_BASELINE_B);

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        TLSCertificateBindingSignatureFormatCheck tlscbsfc = new TLSCertificateBindingSignatureFormatCheck(
                i18nProvider, result, new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        tlscbsfc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setSignatureFormat(SignatureLevel.XAdES_BASELINE_B);

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        TLSCertificateBindingSignatureFormatCheck tlscbsfc = new TLSCertificateBindingSignatureFormatCheck(
                i18nProvider, result, new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        tlscbsfc.execute();

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

        TLSCertificateBindingSignatureFormatCheck tlscbsfc = new TLSCertificateBindingSignatureFormatCheck(
                i18nProvider, result, new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        tlscbsfc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
