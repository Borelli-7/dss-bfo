package eu.europa.esig.dss.validation.process.qualification.certificate.qwac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.validation.process.qualification.certificate.CertQualificationAtTimeBlock;
import eu.europa.esig.dss.validation.process.qualification.certificate.CertificateQualificationBlock;

import java.util.Date;
import java.util.List;

/**
 * Performs qualification determination for a QWAC certificate according to the TS 119 615 process.
 *
 */
public class CertificateQualificationForQWACBlock extends CertificateQualificationBlock {

    /**
     * Default constructor
     *
     * @param i18nProvider             {@link I18nProvider}
     * @param buildingBlocksConclusion {@link XmlConclusion} of BBB for the validating certificate
     * @param validationTime           {@link Date} validation time
     * @param signingCertificate       {@link CertificateWrapper} to be validated
     * @param tlAnalysis               a list of {@link XmlTLAnalysis}
     */
    public CertificateQualificationForQWACBlock(I18nProvider i18nProvider, XmlConclusion buildingBlocksConclusion,
                                                Date validationTime, CertificateWrapper signingCertificate, List<XmlTLAnalysis> tlAnalysis) {
        super(i18nProvider, buildingBlocksConclusion, validationTime, signingCertificate, tlAnalysis);
    }

    @Override
    protected CertQualificationAtTimeBlock getCertQualificationAtIssuanceTimeBlock(List<TrustServiceWrapper> acceptableServices) {
        return new CertQualificationAtTimeForQWACBlock(i18nProvider, ValidationTime.CERTIFICATE_ISSUANCE_TIME, signingCertificate, acceptableServices);
    }

    @Override
    protected CertQualificationAtTimeBlock getCertQualificationAtValidationTimeBlock(List<TrustServiceWrapper> acceptableServices) {
        return new CertQualificationAtTimeForQWACBlock(i18nProvider, ValidationTime.VALIDATION_TIME, validationTime, signingCertificate, acceptableServices);
    }

}
