package eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.QWACProfile;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks whether the certificate presented in the binding is QWAC
 *
 */
public class TLSCertificateBindingQWACCheck extends ChainItem<XmlValidationQWACProcess> {

    /** QWAC Profile of the binding certificate */
    private final QWACProfile qwacProfile;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationQWACProcess}
     * @param qwacProfile {@link QWACProfile}
     * @param constraint {@link LevelRule}
     */
    public TLSCertificateBindingQWACCheck(final I18nProvider i18nProvider, final XmlValidationQWACProcess result,
                                          final QWACProfile qwacProfile, final LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.qwacProfile = qwacProfile;
    }

    @Override
    protected boolean process() {
        return QWACProfile.QWAC_2 == qwacProfile;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.TLS_CERT_BINDING_QWAC2;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.TLS_CERT_BINDING_QWAC2_ANS;
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
