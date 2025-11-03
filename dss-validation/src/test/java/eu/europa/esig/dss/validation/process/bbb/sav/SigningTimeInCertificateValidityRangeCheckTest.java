package eu.europa.esig.dss.validation.process.bbb.sav;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.SigningTimeInCertificateValidityRangeCheck;
import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SigningTimeInCertificateValidityRangeCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        XmlSignature sig = new XmlSignature();
        sig.setClaimedSigningTime(new Date());

        Calendar calendar = Calendar.getInstance();

        XmlCertificate cert = new XmlCertificate();
        calendar.add(Calendar.YEAR, -1);
        cert.setNotBefore(calendar.getTime());
        calendar.add(Calendar.YEAR, 2);
        cert.setNotAfter(calendar.getTime());

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(cert);
        sig.setSigningCertificate(xmlSigningCertificate);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSAV result = new XmlSAV();
        SigningTimeInCertificateValidityRangeCheck<XmlSAV> sricvrc = new SigningTimeInCertificateValidityRangeCheck<>(
                i18nProvider, result, new SignatureWrapper(sig), new LevelConstraintWrapper(constraint));
        sricvrc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void notYetValidTest() {
        XmlSignature sig = new XmlSignature();
        sig.setClaimedSigningTime(new Date());

        Calendar calendar = Calendar.getInstance();

        XmlCertificate cert = new XmlCertificate();
        calendar.add(Calendar.YEAR, 1);
        cert.setNotBefore(calendar.getTime());
        calendar.add(Calendar.YEAR, 2);
        cert.setNotAfter(calendar.getTime());

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(cert);
        sig.setSigningCertificate(xmlSigningCertificate);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSAV result = new XmlSAV();
        SigningTimeInCertificateValidityRangeCheck<XmlSAV> sricvrc = new SigningTimeInCertificateValidityRangeCheck<>(
                i18nProvider, result, new SignatureWrapper(sig), new LevelConstraintWrapper(constraint));
        sricvrc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void expiredTest() {
        XmlSignature sig = new XmlSignature();
        sig.setClaimedSigningTime(new Date());

        Calendar calendar = Calendar.getInstance();

        XmlCertificate cert = new XmlCertificate();
        calendar.add(Calendar.YEAR, -3);
        cert.setNotBefore(calendar.getTime());
        calendar.add(Calendar.YEAR, 2);
        cert.setNotAfter(calendar.getTime());

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(cert);
        sig.setSigningCertificate(xmlSigningCertificate);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSAV result = new XmlSAV();
        SigningTimeInCertificateValidityRangeCheck<XmlSAV> sricvrc = new SigningTimeInCertificateValidityRangeCheck<>(
                i18nProvider, result, new SignatureWrapper(sig), new LevelConstraintWrapper(constraint));
        sricvrc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
