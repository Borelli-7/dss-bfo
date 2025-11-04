package eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlQWACProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * This class verifies whether the QWAC validation has succeeded at least for one QWAC profile
 *
 */
public class QWACValidationResultCheck extends ChainItem<XmlQWACProcess> {

    /** TLS certificate */
    private final XmlValidationQWACProcess[] qwacValidationProcesses;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlQWACProcess}
     * @param qwacValidationProcesses an array of {@link XmlValidationQWACProcess}es
     * @param constraint {@link LevelRule}
     */
    public QWACValidationResultCheck(
            final I18nProvider i18nProvider, final XmlQWACProcess result, final XmlValidationQWACProcess[] qwacValidationProcesses,
            final LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.qwacValidationProcesses = qwacValidationProcesses;
    }

    @Override
    protected boolean process() {
        if (Utils.isArrayNotEmpty(qwacValidationProcesses)) {
            for (XmlValidationQWACProcess qwacProcess : qwacValidationProcesses) {
                if (isValid(qwacProcess)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.QWAC_VALID;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.QWAC_VALID_ANS;
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
