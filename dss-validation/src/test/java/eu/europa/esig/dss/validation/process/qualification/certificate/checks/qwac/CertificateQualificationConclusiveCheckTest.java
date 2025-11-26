package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qwac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificateQualificationProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks.CertificateQualificationConclusiveCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CertificateQualificationConclusiveCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificateQualificationProcess certificateQualification = new XmlCertificateQualificationProcess();
        XmlConclusion xmlConclusion = new XmlConclusion();
        xmlConclusion.setIndication(Indication.PASSED);
        certificateQualification.setConclusion(xmlConclusion);

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        CertificateQualificationConclusiveCheck cqcc = new CertificateQualificationConclusiveCheck(
                i18nProvider, result, certificateQualification, new LevelConstraintWrapper(constraint));
        cqcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void indeterminateTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificateQualificationProcess certificateQualification = new XmlCertificateQualificationProcess();
        XmlConclusion xmlConclusion = new XmlConclusion();
        xmlConclusion.setIndication(Indication.INDETERMINATE);
        certificateQualification.setConclusion(xmlConclusion);

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        CertificateQualificationConclusiveCheck cqcc = new CertificateQualificationConclusiveCheck(
                i18nProvider, result, certificateQualification, new LevelConstraintWrapper(constraint));
        cqcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void failedTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificateQualificationProcess certificateQualification = new XmlCertificateQualificationProcess();
        XmlConclusion xmlConclusion = new XmlConclusion();
        xmlConclusion.setIndication(Indication.FAILED);
        certificateQualification.setConclusion(xmlConclusion);

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        CertificateQualificationConclusiveCheck cqcc = new CertificateQualificationConclusiveCheck(
                i18nProvider, result, certificateQualification, new LevelConstraintWrapper(constraint));
        cqcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
