package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qwac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlGeneralName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSubjectAlternativeNames;
import eu.europa.esig.dss.enumerations.GeneralNameType;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks.QWACDomainNameCheck;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class QWACDomainNameCheckTest extends AbstractTestCheck {

    @Test
    void dnsFullNameTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID("2.5.29.17");
        XmlGeneralName xmlGeneralName = new XmlGeneralName();
        xmlGeneralName.setType(GeneralNameType.DNS_NAME);
        xmlGeneralName.setValue("example.net");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralName);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlSubjectAlternativeNames));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACDomainNameCheck qwacdnc = new QWACDomainNameCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), "example.net", new LevelConstraintWrapper(constraint));
        qwacdnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void dnsAllWildcardTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID("2.5.29.17");
        XmlGeneralName xmlGeneralName = new XmlGeneralName();
        xmlGeneralName.setType(GeneralNameType.DNS_NAME);
        xmlGeneralName.setValue("*");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralName);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlSubjectAlternativeNames));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACDomainNameCheck qwacdnc = new QWACDomainNameCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), "example.net", new LevelConstraintWrapper(constraint));
        qwacdnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void dnsWildcardTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID("2.5.29.17");
        XmlGeneralName xmlGeneralName = new XmlGeneralName();
        xmlGeneralName.setType(GeneralNameType.DNS_NAME);
        xmlGeneralName.setValue("*.example.net");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralName);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlSubjectAlternativeNames));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACDomainNameCheck qwacdnc = new QWACDomainNameCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), "bar.example.net", new LevelConstraintWrapper(constraint));
        qwacdnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void dnsWildcardTwoLevelsTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID("2.5.29.17");
        XmlGeneralName xmlGeneralName = new XmlGeneralName();
        xmlGeneralName.setType(GeneralNameType.DNS_NAME);
        xmlGeneralName.setValue("*.example.net");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralName);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlSubjectAlternativeNames));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACDomainNameCheck qwacdnc = new QWACDomainNameCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), "foo.bar.example.net", new LevelConstraintWrapper(constraint));
        qwacdnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void dnsWildcardNameTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID("2.5.29.17");
        XmlGeneralName xmlGeneralName = new XmlGeneralName();
        xmlGeneralName.setType(GeneralNameType.DNS_NAME);
        xmlGeneralName.setValue("*.example.net");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralName);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlSubjectAlternativeNames));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACDomainNameCheck qwacdnc = new QWACDomainNameCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), "example.net", new LevelConstraintWrapper(constraint));
        qwacdnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void dnsWildcardInvalidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID("2.5.29.17");
        XmlGeneralName xmlGeneralName = new XmlGeneralName();
        xmlGeneralName.setType(GeneralNameType.DNS_NAME);
        xmlGeneralName.setValue("bar.*.example.net");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralName);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlSubjectAlternativeNames));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACDomainNameCheck qwacdnc = new QWACDomainNameCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), "bar.foo.example.net", new LevelConstraintWrapper(constraint));
        qwacdnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void nullSubAltNamesTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACDomainNameCheck qwacdnc = new QWACDomainNameCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), "example.net", new LevelConstraintWrapper(constraint));
        qwacdnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void diffTypeFullNameTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID("2.5.29.17");
        XmlGeneralName xmlGeneralName = new XmlGeneralName();
        xmlGeneralName.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralName.setValue("example.net");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralName);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlSubjectAlternativeNames));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACDomainNameCheck qwacdnc = new QWACDomainNameCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), "example.net", new LevelConstraintWrapper(constraint));
        qwacdnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void ipAddressTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID("2.5.29.17");
        XmlGeneralName xmlGeneralName = new XmlGeneralName();
        xmlGeneralName.setType(GeneralNameType.IP_ADDRESS);
        xmlGeneralName.setValue("127.0.0.1");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralName);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlSubjectAlternativeNames));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACDomainNameCheck qwacdnc = new QWACDomainNameCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), "127.0.0.1", new LevelConstraintWrapper(constraint));
        qwacdnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void ipAddressInvalidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID("2.5.29.17");
        XmlGeneralName xmlGeneralName = new XmlGeneralName();
        xmlGeneralName.setType(GeneralNameType.IP_ADDRESS);
        xmlGeneralName.setValue("127.0.0.1");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralName);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlSubjectAlternativeNames));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACDomainNameCheck qwacdnc = new QWACDomainNameCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), "127.0.10.1", new LevelConstraintWrapper(constraint));
        qwacdnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void ipAddressWildcardTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = new XmlSubjectAlternativeNames();
        xmlSubjectAlternativeNames.setOID("2.5.29.17");
        XmlGeneralName xmlGeneralName = new XmlGeneralName();
        xmlGeneralName.setType(GeneralNameType.IP_ADDRESS);
        xmlGeneralName.setValue("*.0.0.1");
        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralName);
        xmlCertificate.setCertificateExtensions(Collections.singletonList(xmlSubjectAlternativeNames));

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        QWACDomainNameCheck qwacdnc = new QWACDomainNameCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), "127.0.0.1", new LevelConstraintWrapper(constraint));
        qwacdnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
