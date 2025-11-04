package eu.europa.esig.dss.validation.process.qualification.certificate.qwac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificateQualificationProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlQWACProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.QWACProfile;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.QWAC2ValidationProcessBlock;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks.QWACValidationResultCheck;

import java.util.Date;
import java.util.Map;

/**
 * This class runs a validation process for QWAC as per ETSI TS 119 411-5 for a TLS Binding certificate
 * (e.g. 2-QWAC certificate of the TLS Certificate Binding JAdES signature)
 *
 */
public class QWACForTLSBindingCertificateValidationBlock extends Chain<XmlQWACProcess> {

    /** The certificate to determine qualification for */
    private final CertificateWrapper certificate;

    /** Validation time */
    private final Date validationTime;

    /** Map of Basic Building Blocks */
    private final Map<String, XmlBasicBuildingBlocks> bbbs;

    /** Qualification status of the certificate */
    private final XmlCertificateQualificationProcess certificateQualification;

    /** URL of the website to validate the QWAC certificate against */
    private final String websiteUrl;

    /**
     * Default constructor
     *
     * @param i18nProvider the access to translations
     * @param validationTime {@link Date} used to perform the validation
     * @param certificate {@link CertificateWrapper} representing a TLS certificate to be validated
     * @param bbbs map of Basic Building Blocks
     * @param certificateQualification {@link XmlCertificateQualificationProcess}
     * @param websiteUrl {@link String} representing a URL of the website in question
     */
    public QWACForTLSBindingCertificateValidationBlock(final I18nProvider i18nProvider, final Date validationTime,
            final CertificateWrapper certificate, final Map<String, XmlBasicBuildingBlocks> bbbs,
            final XmlCertificateQualificationProcess certificateQualification, final String websiteUrl) {
        super(i18nProvider, new XmlQWACProcess());

        result.setId(certificate.getId());

        this.certificate = certificate;
        this.validationTime = validationTime;
        this.bbbs = bbbs;
        this.certificateQualification = certificateQualification;
        this.websiteUrl = websiteUrl;
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.QWAC_VALIDATION;
    }

    @Override
    protected void initChain() {

        XmlBasicBuildingBlocks certBBB = bbbs.get(certificate.getId());
        if (certBBB == null) {
            throw new IllegalStateException(String.format("The certificate basic validation process shall be performed! " +
                    "No BasicBuildingBlock found for a certificate with Id '%s'", certificate.getId()));
        }

        QWAC2ValidationProcessBlock qwac2Process = new QWAC2ValidationProcessBlock(
                i18nProvider, validationTime, certificate, certBBB.getConclusion(), certificateQualification, websiteUrl);
        XmlValidationQWACProcess qwac2ValidationResult = qwac2Process.execute();
        result.getValidationQWACProcess().add(qwac2ValidationResult);

        ChainItem<XmlQWACProcess> item = firstItem = qwacValidation(qwac2ValidationResult);

        if (isValid(qwac2ValidationResult)) {
            result.setQWACType(qwac2Process.getQWACProfile());
        } else {
            result.setQWACType(QWACProfile.NOT_QWAC);
        }

    }

    private ChainItem<XmlQWACProcess> qwacValidation(XmlValidationQWACProcess... qwacValidationProcesses) {
        return new QWACValidationResultCheck(i18nProvider, result, qwacValidationProcesses, getFailLevelRule());
    }

}
