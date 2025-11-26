package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qwac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlQWACProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks.QWACValidationResultCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class QWACValidationResultCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationQWACProcess qwacProcess = new XmlValidationQWACProcess();
        XmlConclusion xmlConclusion = new XmlConclusion();
        xmlConclusion.setIndication(Indication.PASSED);
        qwacProcess.setConclusion(xmlConclusion);

        XmlQWACProcess result = new XmlQWACProcess();

        QWACValidationResultCheck qwacvrc = new QWACValidationResultCheck(
                i18nProvider, result, new XmlValidationQWACProcess[] { qwacProcess }, new LevelConstraintWrapper(constraint));
        qwacvrc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void validAndInvalidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationQWACProcess qwacProcessValid = new XmlValidationQWACProcess();
        XmlConclusion xmlConclusion = new XmlConclusion();
        xmlConclusion.setIndication(Indication.PASSED);
        qwacProcessValid.setConclusion(xmlConclusion);

        XmlValidationQWACProcess qwacProcessInvalid = new XmlValidationQWACProcess();
        xmlConclusion = new XmlConclusion();
        xmlConclusion.setIndication(Indication.FAILED);
        qwacProcessInvalid.setConclusion(xmlConclusion);

        XmlQWACProcess result = new XmlQWACProcess();

        QWACValidationResultCheck qwacvrc = new QWACValidationResultCheck(
                i18nProvider, result, new XmlValidationQWACProcess[] { qwacProcessValid, qwacProcessInvalid }, new LevelConstraintWrapper(constraint));
        qwacvrc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationQWACProcess qwacProcess = new XmlValidationQWACProcess();
        XmlConclusion xmlConclusion = new XmlConclusion();
        xmlConclusion.setIndication(Indication.INDETERMINATE);
        qwacProcess.setConclusion(xmlConclusion);

        XmlQWACProcess result = new XmlQWACProcess();

        QWACValidationResultCheck qwacvrc = new QWACValidationResultCheck(
                i18nProvider, result, new XmlValidationQWACProcess[] { qwacProcess }, new LevelConstraintWrapper(constraint));
        qwacvrc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void emptyTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlQWACProcess result = new XmlQWACProcess();

        QWACValidationResultCheck qwacvrc = new QWACValidationResultCheck(
                i18nProvider, result, new XmlValidationQWACProcess[] {}, new LevelConstraintWrapper(constraint));
        qwacvrc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
