package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qwac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks.QWACValidityPeriodCheck;
import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class QWACValidityPeriodCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();
        Date currentTime = calendar.getTime();

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -1);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 2);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACValidityPeriodCheck qwavpc = new QWACValidityPeriodCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), currentTime, new LevelConstraintWrapper(constraint));
        qwavpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void notYetValidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();
        Date currentTime = calendar.getTime();

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, 1);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 2);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACValidityPeriodCheck qwavpc = new QWACValidityPeriodCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), currentTime, new LevelConstraintWrapper(constraint));
        qwavpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void expiredTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();
        Date currentTime = calendar.getTime();

        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -3);
        xmlCertificate.setNotBefore(calendar.getTime());

        calendar.add(Calendar.YEAR, 2);
        xmlCertificate.setNotAfter(calendar.getTime());

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACValidityPeriodCheck qwavpc = new QWACValidityPeriodCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), currentTime, new LevelConstraintWrapper(constraint));
        qwavpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
