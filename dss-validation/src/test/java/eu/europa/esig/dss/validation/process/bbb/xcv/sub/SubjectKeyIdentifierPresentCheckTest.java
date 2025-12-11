package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicConstraints;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSubjectKeyIdentifier;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.SubjectKeyIdentifierPresentCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SubjectKeyIdentifierPresentCheckTest extends AbstractTestCheck {

    @Test
    void valid() {
        XmlSubjectKeyIdentifier subjectKeyIdentifier = new XmlSubjectKeyIdentifier();
        subjectKeyIdentifier.setOID(CertificateExtensionEnum.SUBJECT_KEY_IDENTIFIER.getOid());
        subjectKeyIdentifier.setSki(new byte[] { 's', 'k', 'i' });

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(subjectKeyIdentifier);

        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        xc.getCertificateExtensions().add(basicConstraints);

        XmlSubXCV result = new XmlSubXCV();
        SubjectKeyIdentifierPresentCheck skipc = new SubjectKeyIdentifierPresentCheck(i18nProvider, result,
                new CertificateWrapper(xc), new LevelConstraintWrapper(constraint));
        skipc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalid() {
        XmlSubjectKeyIdentifier subjectKeyIdentifier = new XmlSubjectKeyIdentifier();
        subjectKeyIdentifier.setOID(CertificateExtensionEnum.SUBJECT_KEY_IDENTIFIER.getOid());

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(subjectKeyIdentifier);

        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        xc.getCertificateExtensions().add(basicConstraints);

        XmlSubXCV result = new XmlSubXCV();
        SubjectKeyIdentifierPresentCheck skipc = new SubjectKeyIdentifierPresentCheck(i18nProvider, result,
                new CertificateWrapper(xc), new LevelConstraintWrapper(constraint));
        skipc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void notPresent() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();

        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        xc.getCertificateExtensions().add(basicConstraints);

        XmlSubXCV result = new XmlSubXCV();
        SubjectKeyIdentifierPresentCheck skipc = new SubjectKeyIdentifierPresentCheck(i18nProvider, result,
                new CertificateWrapper(xc), new LevelConstraintWrapper(constraint));
        skipc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
