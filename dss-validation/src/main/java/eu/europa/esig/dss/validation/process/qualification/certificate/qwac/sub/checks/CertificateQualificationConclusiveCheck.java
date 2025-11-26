package eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificateQualificationProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks whether the certificate qualification process has been performed successfully
 *
 */
public class CertificateQualificationConclusiveCheck extends ChainItem<XmlValidationQWACProcess> {

    /** Qualification validation process of the certificate */
    private final XmlCertificateQualificationProcess certificateQualification;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationQWACProcess}
     * @param certificateQualification {@link XmlCertificateQualificationProcess}
     * @param constraint {@link LevelRule}
     */
    public CertificateQualificationConclusiveCheck(final I18nProvider i18nProvider, final XmlValidationQWACProcess result,
            final XmlCertificateQualificationProcess certificateQualification, final LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.certificateQualification = certificateQualification;
    }

    @Override
    protected boolean process() {
        return isValidConclusion(certificateQualification.getConclusion());
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.QWAC_CERT_QUAL_CONCLUSIVE;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.QWAC_CERT_QUAL_CONCLUSIVE_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.FAILED;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return null;
    }

}
