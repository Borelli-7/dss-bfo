package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrusted;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ProspectiveCertificateChainAtValidationTimeCheckTest extends AbstractTestCheck {

    @Test
    void certificateExpirationCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Date now = new Date();
        long nowMil = now.getTime();
        XmlCertificate xc = new XmlCertificate();
        XmlTrusted xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(true);
        xmlTrusted.setSunsetDate(new Date(nowMil + 86400000)); // in 24 hours
        xc.setTrusted(xmlTrusted);

        XmlXCV result = new XmlXCV();
        ProspectiveCertificateChainAtValidationTimeCheck pcc = new ProspectiveCertificateChainAtValidationTimeCheck(
                i18nProvider, result, new CertificateWrapper(xc), new Date(), constraint);
        pcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void failedCertificateExpirationCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Date now = new Date();
        long nowMil = now.getTime();
        XmlCertificate xc = new XmlCertificate();
        XmlTrusted xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(true);
        xmlTrusted.setSunsetDate(new Date(nowMil - 86400000)); // 24 hours ago
        xc.setTrusted(xmlTrusted);

        XmlXCV result = new XmlXCV();
        ProspectiveCertificateChainAtValidationTimeCheck pcc = new ProspectiveCertificateChainAtValidationTimeCheck(
                i18nProvider, result, new CertificateWrapper(xc), new Date(), constraint);
        pcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void noSunsetDateTrustedCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();
        XmlTrusted xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(true);
        xc.setTrusted(xmlTrusted);

        XmlXCV result = new XmlXCV();
        ProspectiveCertificateChainAtValidationTimeCheck pcc = new ProspectiveCertificateChainAtValidationTimeCheck(
                i18nProvider, result, new CertificateWrapper(xc), new Date(), constraint);
        pcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void noSunsetDateNotTrustedCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();

        XmlXCV result = new XmlXCV();
        ProspectiveCertificateChainAtValidationTimeCheck pcc = new ProspectiveCertificateChainAtValidationTimeCheck(
                i18nProvider, result, new CertificateWrapper(xc), new Date(), constraint);
        pcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void certChainTrustedCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();

        XmlCertificate ca = new XmlCertificate();
        Date now = new Date();
        long nowMil = now.getTime();
        XmlTrusted xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(true);
        xmlTrusted.setSunsetDate(new Date(nowMil + 86400000)); // in 24 hours
        ca.setTrusted(xmlTrusted);

        XmlChainItem xmlChainItem = new XmlChainItem();
        xmlChainItem.setCertificate(ca);
        xc.setCertificateChain(Collections.singletonList(xmlChainItem));

        XmlXCV result = new XmlXCV();
        ProspectiveCertificateChainAtValidationTimeCheck pcc = new ProspectiveCertificateChainAtValidationTimeCheck(
                i18nProvider, result, new CertificateWrapper(xc), new Date(), constraint);
        pcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void certChainExpiredCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();

        XmlCertificate ca = new XmlCertificate();
        Date now = new Date();
        long nowMil = now.getTime();
        XmlTrusted xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(true);
        xmlTrusted.setSunsetDate(new Date(nowMil - 86400000)); // 24h ago
        ca.setTrusted(xmlTrusted);

        XmlChainItem xmlChainItem = new XmlChainItem();
        xmlChainItem.setCertificate(ca);
        xc.setCertificateChain(Collections.singletonList(xmlChainItem));

        XmlXCV result = new XmlXCV();
        ProspectiveCertificateChainAtValidationTimeCheck pcc = new ProspectiveCertificateChainAtValidationTimeCheck(
                i18nProvider, result, new CertificateWrapper(xc), new Date(), constraint);
        pcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void certChainNotTrustedCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();

        XmlCertificate ca = new XmlCertificate();

        XmlChainItem xmlChainItem = new XmlChainItem();
        xmlChainItem.setCertificate(ca);
        xc.setCertificateChain(Collections.singletonList(xmlChainItem));

        XmlXCV result = new XmlXCV();
        ProspectiveCertificateChainAtValidationTimeCheck pcc = new ProspectiveCertificateChainAtValidationTimeCheck(
                i18nProvider, result, new CertificateWrapper(xc), new Date(), constraint);
        pcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}