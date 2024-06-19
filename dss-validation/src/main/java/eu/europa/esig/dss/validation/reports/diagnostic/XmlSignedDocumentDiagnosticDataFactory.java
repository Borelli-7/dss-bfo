package eu.europa.esig.dss.validation.reports.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.spi.validation.ValidationContext;

import java.util.Date;
import java.util.Objects;

public class XmlSignedDocumentDiagnosticDataFactory {

    private final SignedDocumentDiagnosticDataBuilder diagnosticDataBuilder;

    private DSSDocument document;

    private Date validationTime;

    private ValidationContext validationContext;

    private DigestAlgorithm defaultDigestAlgorithm;

    private TokenExtractionStrategy tokenExtractionStrategy;

    private TokenIdentifierProvider tokenIdentifierProvider;

    public XmlSignedDocumentDiagnosticDataFactory(final SignedDocumentDiagnosticDataBuilder diagnosticDataBuilder) {
        Objects.requireNonNull(diagnosticDataBuilder, "SignedDocumentDiagnosticDataBuilder is null!");
        this.diagnosticDataBuilder = diagnosticDataBuilder;
    }

    public XmlSignedDocumentDiagnosticDataFactory setDocument(DSSDocument document) {
        this.document = document;
        return this;
    }

    public XmlSignedDocumentDiagnosticDataFactory setValidationTime(Date validationTime) {
        this.validationTime = validationTime;
        return this;
    }

    public XmlSignedDocumentDiagnosticDataFactory setValidationContext(ValidationContext validationContext) {
        this.validationContext = validationContext;
        return this;
    }

    public XmlSignedDocumentDiagnosticDataFactory setDefaultDigestAlgorithm(DigestAlgorithm defaultDigestAlgorithm) {
        this.defaultDigestAlgorithm = defaultDigestAlgorithm;
        return this;
    }

    public XmlSignedDocumentDiagnosticDataFactory setTokenExtractionStrategy(TokenExtractionStrategy tokenExtractionStrategy) {
        this.tokenExtractionStrategy = tokenExtractionStrategy;
        return this;
    }

    public XmlSignedDocumentDiagnosticDataFactory setTokenIdentifierProvider(TokenIdentifierProvider tokenIdentifierProvider) {
        this.tokenIdentifierProvider = tokenIdentifierProvider;
        return this;
    }

    public XmlDiagnosticData create() {
        return diagnosticDataBuilder
                .document(document)
                .validationDate(validationTime)
                .foundSignatures(validationContext.getProcessedSignatures())
                .usedTimestamps(validationContext.getProcessedTimestamps())
                .foundEvidenceRecords(validationContext.getProcessedEvidenceRecords())
                .allCertificateSources(validationContext.getAllCertificateSources())
                .documentCertificateSource(validationContext.getDocumentCertificateSource())
                .documentCRLSource(validationContext.getDocumentCRLSource())
                .documentOCSPSource(validationContext.getDocumentOCSPSource())
                .usedCertificates(validationContext.getProcessedCertificates())
                .usedRevocations(validationContext.getProcessedRevocations())
                .defaultDigestAlgorithm(defaultDigestAlgorithm)
                .tokenExtractionStrategy(tokenExtractionStrategy)
                .tokenIdentifierProvider(tokenIdentifierProvider)
                .build();
    }

}
