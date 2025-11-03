package eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Verifies whether the serialization type of the obtained signature is allowed
 *
 */
public class TLSCertificateBindingSignatureSerializationTypeCheck extends ChainItem<XmlValidationQWACProcess> {

    /** The TLS Certificate Binding signature */
    private final SignatureWrapper signature;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationQWACProcess}
     * @param signature {@link SignatureWrapper}
     * @param constraint {@link LevelRule}
     */
    public TLSCertificateBindingSignatureSerializationTypeCheck(final I18nProvider i18nProvider,
            final XmlValidationQWACProcess result, final SignatureWrapper signature, final LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.signature = signature;
    }

    @Override
    protected boolean process() {
        return JWSSerializationType.COMPACT_SERIALIZATION == signature.getJWSSerializationType();
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.TLS_CERT_BINDING_SIG_SER;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.TLS_CERT_BINDING_SIG_SER_ANS;
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
