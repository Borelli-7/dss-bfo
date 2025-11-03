package eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.qwac.QWACUtils;

import java.util.Collections;

/**
 * Verifies that the TLS certificate is present within the TLS Certificate Binding signature
 *
 */
public class TLSCertificateBindingPresentInSignatureCheck extends ChainItem<XmlValidationQWACProcess> {

    /** TLS certificate */
    private final CertificateWrapper tlsCertificate;

    /** The TLS Certificate Binding signature */
    private final SignatureWrapper bindingSignature;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationQWACProcess}
     * @param tlsCertificate {@link CertificateWrapper}
     * @param bindingSignature {@link SignatureWrapper}
     * @param constraint {@link LevelRule}
     */
    public TLSCertificateBindingPresentInSignatureCheck(
            final I18nProvider i18nProvider, final XmlValidationQWACProcess result,
            final CertificateWrapper tlsCertificate, final SignatureWrapper bindingSignature, final LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.tlsCertificate = tlsCertificate;
        this.bindingSignature = bindingSignature;
    }

    @Override
    protected boolean process() {
        return isTLSCertificateIdentified();
    }

    private boolean isTLSCertificateIdentified() {
        return Utils.isCollectionNotEmpty(
                QWACUtils.getIdentifiedTLSCertificates(bindingSignature, Collections.singletonList(tlsCertificate)));
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED_ANS;
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
