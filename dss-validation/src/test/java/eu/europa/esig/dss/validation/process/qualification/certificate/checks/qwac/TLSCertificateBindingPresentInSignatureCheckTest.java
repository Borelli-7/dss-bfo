package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qwac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks.TLSCertificateBindingPresentInSignatureCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TLSCertificateBindingPresentInSignatureCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        xmlCertificate.setId("C-1234");

        XmlSignature xmlSignature = new XmlSignature();

        XmlDigestMatcher digestMatcherOk = new XmlDigestMatcher();
        digestMatcherOk.setType(DigestMatcherType.SIG_D_ENTRY);
        digestMatcherOk.setDataFound(true);
        digestMatcherOk.setDataIntact(true);
        digestMatcherOk.setDocumentName("C-1234");
        xmlSignature.getDigestMatchers().add(digestMatcherOk);

        XmlDigestMatcher digestMatcherKo = new XmlDigestMatcher();
        digestMatcherKo.setType(DigestMatcherType.SIG_D_ENTRY);
        digestMatcherKo.setDataFound(true);
        digestMatcherKo.setDataIntact(true);
        digestMatcherKo.setDocumentName("C-5678");
        xmlSignature.getDigestMatchers().add(digestMatcherKo);

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        TLSCertificateBindingPresentInSignatureCheck tlscbpsc = new TLSCertificateBindingPresentInSignatureCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        tlscbpsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidIdTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        xmlCertificate.setId("C-1234");

        XmlSignature xmlSignature = new XmlSignature();

        XmlDigestMatcher digestMatcherOk = new XmlDigestMatcher();
        digestMatcherOk.setType(DigestMatcherType.SIG_D_ENTRY);
        digestMatcherOk.setDataFound(true);
        digestMatcherOk.setDataIntact(true);
        digestMatcherOk.setDocumentName("C-4321");
        xmlSignature.getDigestMatchers().add(digestMatcherOk);

        XmlDigestMatcher digestMatcherKo = new XmlDigestMatcher();
        digestMatcherKo.setType(DigestMatcherType.SIG_D_ENTRY);
        digestMatcherKo.setDataFound(true);
        digestMatcherKo.setDataIntact(true);
        digestMatcherKo.setDocumentName("C-5678");
        xmlSignature.getDigestMatchers().add(digestMatcherKo);

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        TLSCertificateBindingPresentInSignatureCheck tlscbpsc = new TLSCertificateBindingPresentInSignatureCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        tlscbpsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void notFoundTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        xmlCertificate.setId("C-1234");

        XmlSignature xmlSignature = new XmlSignature();

        XmlDigestMatcher digestMatcherOk = new XmlDigestMatcher();
        digestMatcherOk.setType(DigestMatcherType.SIG_D_ENTRY);
        digestMatcherOk.setDataFound(false);
        digestMatcherOk.setDataIntact(true);
        digestMatcherOk.setDocumentName("C-1234");
        xmlSignature.getDigestMatchers().add(digestMatcherOk);

        XmlDigestMatcher digestMatcherKo = new XmlDigestMatcher();
        digestMatcherKo.setType(DigestMatcherType.SIG_D_ENTRY);
        digestMatcherKo.setDataFound(true);
        digestMatcherKo.setDataIntact(true);
        digestMatcherKo.setDocumentName("C-5678");
        xmlSignature.getDigestMatchers().add(digestMatcherKo);

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        TLSCertificateBindingPresentInSignatureCheck tlscbpsc = new TLSCertificateBindingPresentInSignatureCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        tlscbpsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void notIntactTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        xmlCertificate.setId("C-1234");

        XmlSignature xmlSignature = new XmlSignature();

        XmlDigestMatcher digestMatcherOk = new XmlDigestMatcher();
        digestMatcherOk.setType(DigestMatcherType.SIG_D_ENTRY);
        digestMatcherOk.setDataFound(true);
        digestMatcherOk.setDataIntact(false);
        digestMatcherOk.setDocumentName("C-1234");
        xmlSignature.getDigestMatchers().add(digestMatcherOk);

        XmlDigestMatcher digestMatcherKo = new XmlDigestMatcher();
        digestMatcherKo.setType(DigestMatcherType.SIG_D_ENTRY);
        digestMatcherKo.setDataFound(true);
        digestMatcherKo.setDataIntact(true);
        digestMatcherKo.setDocumentName("C-5678");
        xmlSignature.getDigestMatchers().add(digestMatcherKo);

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        TLSCertificateBindingPresentInSignatureCheck tlscbpsc = new TLSCertificateBindingPresentInSignatureCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        tlscbpsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void diffTypeTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        xmlCertificate.setId("C-1234");

        XmlSignature xmlSignature = new XmlSignature();

        XmlDigestMatcher digestMatcherOk = new XmlDigestMatcher();
        digestMatcherOk.setType(DigestMatcherType.REFERENCE);
        digestMatcherOk.setDataFound(true);
        digestMatcherOk.setDataIntact(true);
        digestMatcherOk.setDocumentName("C-1234");
        xmlSignature.getDigestMatchers().add(digestMatcherOk);

        XmlDigestMatcher digestMatcherKo = new XmlDigestMatcher();
        digestMatcherKo.setType(DigestMatcherType.SIG_D_ENTRY);
        digestMatcherKo.setDataFound(true);
        digestMatcherKo.setDataIntact(true);
        digestMatcherKo.setDocumentName("C-5678");
        xmlSignature.getDigestMatchers().add(digestMatcherKo);

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        TLSCertificateBindingPresentInSignatureCheck tlscbpsc = new TLSCertificateBindingPresentInSignatureCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        tlscbpsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void emptyTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xmlCertificate = new XmlCertificate();
        xmlCertificate.setId("C-1234");

        XmlSignature xmlSignature = new XmlSignature();

        XmlValidationQWACProcess result = new XmlValidationQWACProcess();

        TLSCertificateBindingPresentInSignatureCheck tlscbpsc = new TLSCertificateBindingPresentInSignatureCheck(
                i18nProvider, result, new CertificateWrapper(xmlCertificate), new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        tlscbpsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
