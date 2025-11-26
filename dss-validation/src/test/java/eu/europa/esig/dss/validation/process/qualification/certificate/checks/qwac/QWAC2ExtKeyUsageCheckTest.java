package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qwac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlExtendedKeyUsages;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks.QWAC2ExtKeyUsageCheck;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class QWAC2ExtKeyUsageCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlExtendedKeyUsages xmlExtendedKeyUsages = new XmlExtendedKeyUsages();
        xmlExtendedKeyUsages.setOID("2.5.29.37");
        XmlOID xmlOID = new XmlOID();
        xmlOID.setValue("0.4.0.194115.0.1.0");
        xmlExtendedKeyUsages.getExtendedKeyUsageOid().add(xmlOID);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlExtendedKeyUsages));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWAC2ExtKeyUsageCheck cqcc = new QWAC2ExtKeyUsageCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), new LevelConstraintWrapper(constraint));
        cqcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlExtendedKeyUsages xmlExtendedKeyUsages = new XmlExtendedKeyUsages();
        xmlExtendedKeyUsages.setOID("2.5.29.37");
        XmlOID xmlOID = new XmlOID();
        xmlOID.setValue("0.1.2.4.5");
        xmlExtendedKeyUsages.getExtendedKeyUsageOid().add(xmlOID);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlExtendedKeyUsages));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWAC2ExtKeyUsageCheck cqcc = new QWAC2ExtKeyUsageCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), new LevelConstraintWrapper(constraint));
        cqcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void multipleValuesTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlExtendedKeyUsages xmlExtendedKeyUsages = new XmlExtendedKeyUsages();
        xmlExtendedKeyUsages.setOID("2.5.29.37");
        XmlOID xmlOID1 = new XmlOID();
        xmlOID1.setValue("0.4.0.194115.0.1.0");
        xmlExtendedKeyUsages.getExtendedKeyUsageOid().add(xmlOID1);
        XmlOID xmlOID2 = new XmlOID();
        xmlOID2.setValue("0.1.2.4.5");
        xmlExtendedKeyUsages.getExtendedKeyUsageOid().add(xmlOID2);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlExtendedKeyUsages));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWAC2ExtKeyUsageCheck cqcc = new QWAC2ExtKeyUsageCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), new LevelConstraintWrapper(constraint));
        cqcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void emptyTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlExtendedKeyUsages xmlExtendedKeyUsages = new XmlExtendedKeyUsages();
        xmlExtendedKeyUsages.setOID("2.5.29.37");
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlExtendedKeyUsages));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWAC2ExtKeyUsageCheck cqcc = new QWAC2ExtKeyUsageCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), new LevelConstraintWrapper(constraint));
        cqcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void noExtKeyUsageTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWAC2ExtKeyUsageCheck cqcc = new QWAC2ExtKeyUsageCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), new LevelConstraintWrapper(constraint));
        cqcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
