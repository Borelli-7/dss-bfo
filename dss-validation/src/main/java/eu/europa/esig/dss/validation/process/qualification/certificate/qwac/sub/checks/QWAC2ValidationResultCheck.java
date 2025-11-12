package eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlQWACProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;

/**
 * This class verifies whether the QWAC validation has succeeded for 2-QWAC profile
 *
 */
public class QWAC2ValidationResultCheck extends QWACValidationResultCheck {

    /**
     * Default constructor
     *
     * @param i18nProvider            {@link I18nProvider}
     * @param result                  {@link XmlQWACProcess}
     * @param qwacValidationProcesses an array of {@link XmlValidationQWACProcess}es
     * @param constraint              {@link LevelRule}
     */
    public QWAC2ValidationResultCheck(final I18nProvider i18nProvider, final XmlQWACProcess result,
                                      final XmlValidationQWACProcess[] qwacValidationProcesses, final LevelRule constraint) {
        super(i18nProvider, result, qwacValidationProcesses, constraint);
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.QWAC_VALID_ANS_2;
    }

}
