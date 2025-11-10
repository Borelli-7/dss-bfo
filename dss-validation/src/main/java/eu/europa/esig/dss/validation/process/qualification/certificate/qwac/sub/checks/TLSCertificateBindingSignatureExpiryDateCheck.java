package eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.qwac.QWACUtils;

import java.util.Date;
import java.util.List;

/**
 * Verifies the validity of the TLS Certificate Binding signature
 *
 */
public class TLSCertificateBindingSignatureExpiryDateCheck extends ChainItem<XmlValidationQWACProcess> {

    /** Diagnostic data */
    private final DiagnosticData diagnosticData;

    /** The TLS Certificate Binding signature */
    private final SignatureWrapper signature;

    /** Current validation time */
    private final Date currentTime;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationQWACProcess}
     * @param diagnosticData {@link DiagnosticData}
     * @param currentTime {@link Date}
     * @param signature {@link SignatureWrapper}
     * @param constraint {@link LevelRule}
     */
    public TLSCertificateBindingSignatureExpiryDateCheck(final I18nProvider i18nProvider, final XmlValidationQWACProcess result,
            final DiagnosticData diagnosticData, final Date currentTime, final SignatureWrapper signature,
            final LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.diagnosticData = diagnosticData;
        this.currentTime = currentTime;
        this.signature = signature;
    }

    @Override
    protected boolean process() {
        /*
         * The maximum effective expiry time is whichever is soonest of this field,
         * the longest-lived TLS certificate identified in the sigD member payload (below),
         * or the notAfter time of the signing certificate.
         */
        if (signature.getExpirationTime() != null && !currentTime.before(signature.getExpirationTime())) {
            return false;
        }
        for (CertificateWrapper certificate : getIdentifiedTLSCertificates()) {
            if (certificate.getNotAfter() != null && !currentTime.before(certificate.getNotAfter())) {
                return false;
            }
        }
        if (signature.getSigningCertificate() != null && signature.getSigningCertificate().getNotAfter() != null
                && !currentTime.before(signature.getSigningCertificate().getNotAfter())) {
            return false;
        }
        return true;
    }

    private List<CertificateWrapper> getIdentifiedTLSCertificates() {
        return QWACUtils.getIdentifiedTLSCertificates(signature, diagnosticData.getUsedCertificates());
    }

    @Override
    protected String buildAdditionalInfo() {
        if (signature.getExpirationTime() != null && !currentTime.before(signature.getExpirationTime())) {
            return i18nProvider.getMessage(MessageTag.QWAC_EXPIRY_EXP, ValidationProcessUtils.getFormattedDate(currentTime),
                    ValidationProcessUtils.getFormattedDate(signature.getExpirationTime()));
        }
        for (CertificateWrapper certificate : getIdentifiedTLSCertificates()) {
            if (certificate.getNotAfter() != null && !currentTime.before(certificate.getNotAfter())) {
                return i18nProvider.getMessage(MessageTag.QWAC_EXPIRY_EXP, ValidationProcessUtils.getFormattedDate(currentTime),
                        ValidationProcessUtils.getFormattedDate(certificate.getNotAfter()), certificate.getId());
            }
        }
        if (signature.getSigningCertificate() != null && signature.getSigningCertificate().getNotAfter() != null
                && !currentTime.before(signature.getSigningCertificate().getNotAfter())) {
            return i18nProvider.getMessage(MessageTag.QWAC_EXPIRY_EXP, ValidationProcessUtils.getFormattedDate(currentTime),
                    ValidationProcessUtils.getFormattedDate(signature.getSigningCertificate().getNotAfter()),
                    signature.getSigningCertificate().getId());
        }
        return null;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE_ANS;
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
