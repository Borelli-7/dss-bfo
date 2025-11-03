package eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Verifies the basic validation result of a JADES signature on the TLS Certificate Binding
 *
 */
public class TLSCertificateBindingSignatureValidationResultCheck extends ChainItem<XmlValidationQWACProcess> {

    /** Basic Validation conclusion of the TLS Certificate Binding signature */
    private final XmlConclusion bindingSignatureBasicValidationConclusion;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationQWACProcess}
     * @param bindingSignatureBasicValidationConclusion {@link XmlConclusion}
     * @param constraint {@link LevelRule}
     */
    public TLSCertificateBindingSignatureValidationResultCheck(
            final I18nProvider i18nProvider, final XmlValidationQWACProcess result,
            final XmlConclusion bindingSignatureBasicValidationConclusion, final LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.bindingSignatureBasicValidationConclusion = bindingSignatureBasicValidationConclusion;
    }

    @Override
    protected boolean process() {
        return isValidConclusion(bindingSignatureBasicValidationConclusion);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.TLS_CERT_BINDING_SIG_VALID;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.TLS_CERT_BINDING_SIG_VALID_ANS;
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
