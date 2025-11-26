package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qwac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.QWACProfile;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks.TLSCertificateBindingQWACCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TLSCertificateBindingQWACCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        TLSCertificateBindingQWACCheck tlscbqwacc = new TLSCertificateBindingQWACCheck(
                i18nProvider, result, QWACProfile.QWAC_2, new LevelConstraintWrapper(constraint));
        tlscbqwacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        TLSCertificateBindingQWACCheck tlscbqwacc = new TLSCertificateBindingQWACCheck(
                i18nProvider, result, QWACProfile.NOT_QWAC, new LevelConstraintWrapper(constraint));
        tlscbqwacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void nullTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        TLSCertificateBindingQWACCheck tlscbqwacc = new TLSCertificateBindingQWACCheck(
                i18nProvider, result, null, new LevelConstraintWrapper(constraint));
        tlscbqwacc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
