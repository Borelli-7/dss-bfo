package eu.europa.esig.dss.validation.process.qualification.signature.qwac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificateQualificationProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusionWithProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlQWACProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.QWACForTLSBindingCertificateValidationBlock;
import eu.europa.esig.dss.validation.process.qualification.signature.SignatureQualificationBlock;

import java.util.List;
import java.util.Map;

public class TLSBindingSignatureQualificationBlock extends SignatureQualificationBlock {

    /** Map of Basic Building Blocks */
    private final Map<String, XmlBasicBuildingBlocks> bbbs;

    /** URL of the website to validate the QWAC certificate against */
    private final String websiteUrl;

    /**
     * Default constructor
     *
     * @param i18nProvider         {@link I18nProvider}
     * @param bbbs                 a map of {@link XmlBasicBuildingBlocks}
     * @param etsi319102validation {@link XmlConstraintsConclusionWithProofOfExistence}
     *                             result of signature validation process as in EN 319 102-1
     * @param signingCertificate   {@link CertificateWrapper} signing certificate used to create the signature
     * @param tlAnalysis           a list of performed {@link XmlTLAnalysis}
     * @param websiteUrl           {@link String}
     */
    public TLSBindingSignatureQualificationBlock(final I18nProvider i18nProvider,  final Map<String, XmlBasicBuildingBlocks> bbbs,
            final XmlConstraintsConclusionWithProofOfExistence etsi319102validation, final CertificateWrapper signingCertificate,
            final List<XmlTLAnalysis> tlAnalysis, final String websiteUrl) {
        super(i18nProvider, etsi319102validation, signingCertificate, tlAnalysis);

        this.bbbs = bbbs;
        this.websiteUrl = websiteUrl;
    }

    @Override
    protected void initChain() {
        super.initChain();

        XmlCertificateQualificationProcess xmlCertificateQualificationProcess = new XmlCertificateQualificationProcess();
        xmlCertificateQualificationProcess.getValidationCertificateQualification().addAll(result.getValidationCertificateQualification());

        QWACForTLSBindingCertificateValidationBlock qwacForTLSBindingValidationBlock = new QWACForTLSBindingCertificateValidationBlock(
                i18nProvider, bestSignatureTime, signingCertificate, bbbs, xmlCertificateQualificationProcess, websiteUrl);
        XmlQWACProcess qwacProcess = qwacForTLSBindingValidationBlock.execute();
        result.setQWACProcess(qwacProcess);
    }

}
