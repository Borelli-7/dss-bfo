package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qwac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks.QualifiedCertificateForWSAAtTimeCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class QualifiedCertificateForWSAAtTimeCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationCertificateQualification certificateQualification = new XmlValidationCertificateQualification();
        certificateQualification.setCertificateQualification(CertificateQualification.QCERT_FOR_WSA);
        certificateQualification.setValidationTime(ValidationTime.VALIDATION_TIME);

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QualifiedCertificateForWSAAtTimeCheck qcwsat = new QualifiedCertificateForWSAAtTimeCheck(
                i18nProvider, result, certificateQualification, new LevelConstraintWrapper(constraint));
        qcwsat.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationCertificateQualification certificateQualification = new XmlValidationCertificateQualification();
        certificateQualification.setCertificateQualification(CertificateQualification.QCERT_FOR_ESIG);
        certificateQualification.setValidationTime(ValidationTime.VALIDATION_TIME);

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QualifiedCertificateForWSAAtTimeCheck qcwsat = new QualifiedCertificateForWSAAtTimeCheck(
                i18nProvider, result, certificateQualification, new LevelConstraintWrapper(constraint));
        qcwsat.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void notQualifiedTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationCertificateQualification certificateQualification = new XmlValidationCertificateQualification();
        certificateQualification.setCertificateQualification(CertificateQualification.CERT_FOR_WSA);
        certificateQualification.setValidationTime(ValidationTime.VALIDATION_TIME);

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QualifiedCertificateForWSAAtTimeCheck qcwsat = new QualifiedCertificateForWSAAtTimeCheck(
                i18nProvider, result, certificateQualification, new LevelConstraintWrapper(constraint));
        qcwsat.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
