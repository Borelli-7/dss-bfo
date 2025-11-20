package eu.europa.esig.dss.validation.process.qualification.certificate.qwac;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.validation.process.qualification.certificate.CertQualificationAtTimeBlock;

import java.util.Date;
import java.util.List;

/**
 * This class determines certificates qualification status as per ETSI TS 119 615 at the given time for a QWAC.
 *
 */
public class CertQualificationAtTimeForQWACBlock extends CertQualificationAtTimeBlock {

    /**
     * Constructor to instantiate the validation at the certificate's issuance time
     *
     * @param i18nProvider {@link I18nProvider}
     * @param validationTime {@link ValidationTime}
     * @param signingCertificate {@link CertificateWrapper} to get qualification for
     * @param acceptableServices list of {@link TrustServiceWrapper}s
     */
    public CertQualificationAtTimeForQWACBlock(I18nProvider i18nProvider, ValidationTime validationTime,
                                               CertificateWrapper signingCertificate, List<TrustServiceWrapper> acceptableServices) {
        super(i18nProvider, validationTime, signingCertificate, acceptableServices);
    }

    /**
     * Constructor to instantiate the validation at the validation time
     *
     * @param i18nProvider {@link I18nProvider}
     * @param validationTime {@link ValidationTime}
     * @param date {@link Date}
     * @param signingCertificate {@link CertificateWrapper} to get qualification for
     * @param acceptableServices list of {@link TrustServiceWrapper}s
     */
    public CertQualificationAtTimeForQWACBlock(I18nProvider i18nProvider, ValidationTime validationTime, Date date,
                                               CertificateWrapper signingCertificate, List<TrustServiceWrapper> acceptableServices) {
        super(i18nProvider, validationTime, date, signingCertificate, acceptableServices);
    }

    @Override
    protected boolean executeQSCDCheck() {
        return false; // not required for a QWAC
    }

}
