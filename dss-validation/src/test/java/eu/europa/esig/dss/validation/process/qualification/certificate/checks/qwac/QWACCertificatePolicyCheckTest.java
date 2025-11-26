package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qwac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicies;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicy;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.QWACProfile;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks.QWACCertificatePolicyCheck;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class QWACCertificatePolicyCheckTest extends AbstractTestCheck {

    @Test
    void valid1QWACWithQCPTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlCertificatePolicies xmlCertificatePolicies = new XmlCertificatePolicies();
        xmlCertificatePolicies.setOID("2.5.29.32");
        XmlCertificatePolicy xmlCertificatePolicy = new XmlCertificatePolicy();
        xmlCertificatePolicy.setValue("0.4.0.194112.1.4");
        xmlCertificatePolicies.getCertificatePolicy().add(xmlCertificatePolicy);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlCertificatePolicies));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACCertificatePolicyCheck qwaccpc = new QWACCertificatePolicyCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), QWACProfile.QWAC_1, new LevelConstraintWrapper(constraint));
        qwaccpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void valid1QWACWithQNCPTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlCertificatePolicies xmlCertificatePolicies = new XmlCertificatePolicies();
        xmlCertificatePolicies.setOID("2.5.29.32");
        XmlCertificatePolicy xmlCertificatePolicy = new XmlCertificatePolicy();
        xmlCertificatePolicy.setValue("0.4.0.194112.1.5");
        xmlCertificatePolicies.getCertificatePolicy().add(xmlCertificatePolicy);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlCertificatePolicies));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACCertificatePolicyCheck qwaccpc = new QWACCertificatePolicyCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), QWACProfile.QWAC_1, new LevelConstraintWrapper(constraint));
        qwaccpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalid1QWACWithQNCPWebGenTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlCertificatePolicies xmlCertificatePolicies = new XmlCertificatePolicies();
        xmlCertificatePolicies.setOID("2.5.29.32");
        XmlCertificatePolicy xmlCertificatePolicy = new XmlCertificatePolicy();
        xmlCertificatePolicy.setValue("0.4.0.194112.1.6");
        xmlCertificatePolicies.getCertificatePolicy().add(xmlCertificatePolicy);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlCertificatePolicies));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACCertificatePolicyCheck qwaccpc = new QWACCertificatePolicyCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), QWACProfile.QWAC_1, new LevelConstraintWrapper(constraint));
        qwaccpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void valid2QWACWithQNCPWebGenTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlCertificatePolicies xmlCertificatePolicies = new XmlCertificatePolicies();
        xmlCertificatePolicies.setOID("2.5.29.32");
        XmlCertificatePolicy xmlCertificatePolicy = new XmlCertificatePolicy();
        xmlCertificatePolicy.setValue("0.4.0.194112.1.6");
        xmlCertificatePolicies.getCertificatePolicy().add(xmlCertificatePolicy);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlCertificatePolicies));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACCertificatePolicyCheck qwaccpc = new QWACCertificatePolicyCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), QWACProfile.QWAC_2, new LevelConstraintWrapper(constraint));
        qwaccpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalid2QWACWithQCPTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlCertificatePolicies xmlCertificatePolicies = new XmlCertificatePolicies();
        xmlCertificatePolicies.setOID("2.5.29.32");
        XmlCertificatePolicy xmlCertificatePolicy = new XmlCertificatePolicy();
        xmlCertificatePolicy.setValue("0.4.0.194112.1.4");
        xmlCertificatePolicies.getCertificatePolicy().add(xmlCertificatePolicy);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlCertificatePolicies));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACCertificatePolicyCheck qwaccpc = new QWACCertificatePolicyCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), QWACProfile.QWAC_2, new LevelConstraintWrapper(constraint));
        qwaccpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void invalid2QWACWithQNCPTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlCertificatePolicies xmlCertificatePolicies = new XmlCertificatePolicies();
        xmlCertificatePolicies.setOID("2.5.29.32");
        XmlCertificatePolicy xmlCertificatePolicy = new XmlCertificatePolicy();
        xmlCertificatePolicy.setValue("0.4.0.194112.1.5");
        xmlCertificatePolicies.getCertificatePolicy().add(xmlCertificatePolicy);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlCertificatePolicies));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACCertificatePolicyCheck qwaccpc = new QWACCertificatePolicyCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), QWACProfile.QWAC_2, new LevelConstraintWrapper(constraint));
        qwaccpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void noPolicy1QWACTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACCertificatePolicyCheck qwaccpc = new QWACCertificatePolicyCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), QWACProfile.QWAC_1, new LevelConstraintWrapper(constraint));
        qwaccpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void noPolicy2QWACTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACCertificatePolicyCheck qwaccpc = new QWACCertificatePolicyCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), QWACProfile.QWAC_2, new LevelConstraintWrapper(constraint));
        qwaccpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void multiplePolicies1QWACTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlCertificatePolicies xmlCertificatePolicies = new XmlCertificatePolicies();
        xmlCertificatePolicies.setOID("2.5.29.32");
        XmlCertificatePolicy xmlCertificatePolicy1 = new XmlCertificatePolicy();
        xmlCertificatePolicy1.setValue("0.4.0.194112.1.4");
        xmlCertificatePolicies.getCertificatePolicy().add(xmlCertificatePolicy1);
        XmlCertificatePolicy xmlCertificatePolicy2 = new XmlCertificatePolicy();
        xmlCertificatePolicy2.setValue("0.4.0.194112.1.6");
        xmlCertificatePolicies.getCertificatePolicy().add(xmlCertificatePolicy2);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlCertificatePolicies));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACCertificatePolicyCheck qwaccpc = new QWACCertificatePolicyCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), QWACProfile.QWAC_1, new LevelConstraintWrapper(constraint));
        qwaccpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void multiplePolicies2QWACTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlCertificatePolicies xmlCertificatePolicies = new XmlCertificatePolicies();
        xmlCertificatePolicies.setOID("2.5.29.32");
        XmlCertificatePolicy xmlCertificatePolicy1 = new XmlCertificatePolicy();
        xmlCertificatePolicy1.setValue("0.4.0.194112.1.4");
        xmlCertificatePolicies.getCertificatePolicy().add(xmlCertificatePolicy1);
        XmlCertificatePolicy xmlCertificatePolicy2 = new XmlCertificatePolicy();
        xmlCertificatePolicy2.setValue("0.4.0.194112.1.6");
        xmlCertificatePolicies.getCertificatePolicy().add(xmlCertificatePolicy2);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlCertificatePolicies));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACCertificatePolicyCheck qwaccpc = new QWACCertificatePolicyCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), QWACProfile.QWAC_2, new LevelConstraintWrapper(constraint));
        qwaccpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
