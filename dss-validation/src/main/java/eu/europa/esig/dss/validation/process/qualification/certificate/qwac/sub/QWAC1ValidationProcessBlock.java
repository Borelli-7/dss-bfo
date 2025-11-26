package eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificateQualificationProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.QWACProfile;
import eu.europa.esig.dss.i18n.I18nProvider;

import java.util.Date;

/**
 * Performs validation of the 1-QWAC profile as per ETSI TS 119 411-5 part "4.1 1-QWAC Approach"
 *
 */
public class QWAC1ValidationProcessBlock extends AbstractQWACValidationProcessBlock {

    /**
     * Common constructor
     *
     * @param i18nProvider the access to translations
     * @param validationTime {@link Date} used to perform the validation
     * @param certificate {@link CertificateWrapper} representing a TLS certificate to be validated
     * @param buildingBlocksConclusion {@link XmlConclusion}
     * @param certificateQualification {@link XmlCertificateQualificationProcess}
     * @param websiteUrl {@link String}
     */
    public QWAC1ValidationProcessBlock(final I18nProvider i18nProvider, final Date validationTime,
                                       final CertificateWrapper certificate, final XmlConclusion buildingBlocksConclusion,
                                       final XmlCertificateQualificationProcess certificateQualification, final String websiteUrl) {
        super(i18nProvider, validationTime, certificate, buildingBlocksConclusion, certificateQualification, websiteUrl);
    }

    @Override
    public QWACProfile getQWACProfile() {
        return QWACProfile.QWAC_1;
    }

}
