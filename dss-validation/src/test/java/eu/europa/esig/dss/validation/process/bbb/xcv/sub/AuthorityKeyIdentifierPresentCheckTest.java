package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAuthorityKeyIdentifier;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicConstraints;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.AuthorityKeyIdentifierPresentCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuthorityKeyIdentifierPresentCheckTest extends AbstractTestCheck {

    @Test
    void valid() {
        XmlAuthorityKeyIdentifier authorityKeyIdentifier = new XmlAuthorityKeyIdentifier();
        authorityKeyIdentifier.setOID(CertificateExtensionEnum.AUTHORITY_KEY_IDENTIFIER.getOid());
        authorityKeyIdentifier.setKeyIdentifier(new byte[] { 'a', 'k', 'i' });

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(authorityKeyIdentifier);

        XmlCertificate ca = new XmlCertificate();
        XmlSigningCertificate caCert = new XmlSigningCertificate();
        caCert.setCertificate(ca);
        xc.setSigningCertificate(caCert);

        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        ca.getCertificateExtensions().add(basicConstraints);

        XmlSubXCV result = new XmlSubXCV();
        AuthorityKeyIdentifierPresentCheck skipc = new AuthorityKeyIdentifierPresentCheck(i18nProvider, result,
                new CertificateWrapper(xc), new LevelConstraintWrapper(constraint));
        skipc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalid() {
        XmlAuthorityKeyIdentifier authorityKeyIdentifier = new XmlAuthorityKeyIdentifier();
        authorityKeyIdentifier.setOID(CertificateExtensionEnum.AUTHORITY_KEY_IDENTIFIER.getOid());

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(authorityKeyIdentifier);

        XmlCertificate ca = new XmlCertificate();
        XmlSigningCertificate caCert = new XmlSigningCertificate();
        caCert.setCertificate(ca);
        xc.setSigningCertificate(caCert);

        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        ca.getCertificateExtensions().add(basicConstraints);

        XmlSubXCV result = new XmlSubXCV();
        AuthorityKeyIdentifierPresentCheck skipc = new AuthorityKeyIdentifierPresentCheck(i18nProvider, result,
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

        XmlCertificate ca = new XmlCertificate();
        XmlSigningCertificate caCert = new XmlSigningCertificate();
        caCert.setCertificate(ca);
        xc.setSigningCertificate(caCert);

        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        basicConstraints.setCA(true);
        ca.getCertificateExtensions().add(basicConstraints);

        XmlSubXCV result = new XmlSubXCV();
        AuthorityKeyIdentifierPresentCheck skipc = new AuthorityKeyIdentifierPresentCheck(i18nProvider, result,
                new CertificateWrapper(xc), new LevelConstraintWrapper(constraint));
        skipc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
