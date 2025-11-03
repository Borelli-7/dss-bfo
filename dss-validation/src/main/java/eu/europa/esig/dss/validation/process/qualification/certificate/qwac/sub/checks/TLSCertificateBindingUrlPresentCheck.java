package eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks whether an HTTP 'Link' response header (as defined in IETF RFC 8288 [6]),
 * with a rel value of tls-certificate-binding, has been found.
 *
 */
public class TLSCertificateBindingUrlPresentCheck extends ChainItem<XmlValidationQWACProcess> {

    /** The TLS Certificate Binding URL */
    private final String tlsCertificateBindingUrl;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationQWACProcess}
     * @param tlsCertificateBindingUrl {@link String}
     * @param constraint {@link LevelRule}
     */
    public TLSCertificateBindingUrlPresentCheck(final I18nProvider i18nProvider, final XmlValidationQWACProcess result,
                                                final String tlsCertificateBindingUrl, final LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.tlsCertificateBindingUrl = tlsCertificateBindingUrl;
    }

    @Override
    protected boolean process() {
        return tlsCertificateBindingUrl != null;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.TLS_CERT_BINDING_URL;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.TLS_CERT_BINDING_URL_ANS;
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
