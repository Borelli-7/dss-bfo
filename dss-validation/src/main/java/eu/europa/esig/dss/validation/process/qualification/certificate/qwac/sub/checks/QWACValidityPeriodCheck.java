package eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateValidityRangeCheck;

import java.util.Date;

/**
 * This class verifies the validity period of the QWAC certificate against the current date and time
 *
 */
public class QWACValidityPeriodCheck extends CertificateValidityRangeCheck<XmlValidationQWACProcess> {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationQWACProcess}
     * @param certificate {@link CertificateWrapper}
     * @param currentTime {@link Date}
     * @param constraint {@link LevelRule}
     */
    public QWACValidityPeriodCheck(final I18nProvider i18nProvider, final XmlValidationQWACProcess result,
                                      final CertificateWrapper certificate, final Date currentTime, final LevelRule constraint) {
        super(i18nProvider, result, certificate, currentTime, constraint);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.QWAC_VAL_PERIOD;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.QWAC_VAL_PERIOD_ANS;
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
