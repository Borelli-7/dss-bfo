package eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.CertificatePolicy;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.QWACProfile;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Arrays;
import java.util.List;

/**
 * Verifies whether the certificate has been issued under the appropriate QWAC certificate policy
 *
 */
public class QWACCertificatePolicyCheck extends ChainItem<XmlValidationQWACProcess> {

    /** Certificate to be validates */
    private final CertificateWrapper certificate;

    /** QWAC validation profile */
    private final QWACProfile qwacProfile;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationQWACProcess}
     * @param certificate {@link CertificateWrapper}
     * @param qwacProfile {@link QWACProfile}
     * @param constraint {@link LevelRule}
     */
    public QWACCertificatePolicyCheck(final I18nProvider i18nProvider, final XmlValidationQWACProcess result,
                                      final CertificateWrapper certificate, final QWACProfile qwacProfile, final LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
        this.qwacProfile = qwacProfile;
    }

    @Override
    protected boolean process() {
        switch (qwacProfile) {
            case QWAC_1:
                return certificatePolicyMatch(CertificatePolicy.QCP_WEB, CertificatePolicy.QNCP_WEB);
            case QWAC_2:
                return certificatePolicyMatch(CertificatePolicy.QNCP_WEB_GEN);
            default:
                throw new UnsupportedOperationException(String.format("The QWAC profile '%s' is not supported!", qwacProfile));
        }
    }

    private boolean certificatePolicyMatch(CertificatePolicy... policies) {
        List<String> certificatePoliciesOids = certificate.getCertificatePoliciesOids();
        return Utils.isCollectionNotEmpty(certificatePoliciesOids) &&
                certificatePoliciesOids.stream().anyMatch(k -> Arrays.stream(policies).anyMatch(m -> m.getOid().equals(k)));
    }

    @Override
    protected XmlMessage buildConstraintMessage() {
        return buildXmlMessage(MessageTag.QWAC_CERT_POLICY,
                ValidationProcessUtils.getQWACValidationMessageTag(qwacProfile));
    }

    @Override
    protected XmlMessage buildErrorMessage() {
        return buildXmlMessage(MessageTag.QWAC_CERT_POLICY_ANS,
                ValidationProcessUtils.getQWACValidationMessageTag(qwacProfile));
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
