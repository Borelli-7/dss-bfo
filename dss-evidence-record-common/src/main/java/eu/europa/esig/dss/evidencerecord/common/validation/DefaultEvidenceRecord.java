package eu.europa.esig.dss.evidencerecord.common.validation;

import eu.europa.esig.dss.evidencerecord.common.validation.identifier.EvidenceRecordIdentifierBuilder;
import eu.europa.esig.dss.evidencerecord.common.validation.scope.EvidenceRecordScopeFinder;
import eu.europa.esig.dss.evidencerecord.common.validation.timestamp.EvidenceRecordTimestampSource;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Default representation of an Evidence Record
 *
 */
public abstract class DefaultEvidenceRecord implements EvidenceRecord {

    /**
     * The name of the evidence record document
     */
    private String filename;

    /**
     * Contains a list of documents time-stamped within a reduced HashTree
     */
    private List<DSSDocument> detachedContents = new ArrayList<>();

    /**
     * Represents a structure of the evidence record
     */
    private List<? extends ArchiveTimeStampChainObject> archiveTimeStampSequence;

    /** Cached instance of timestamp source */
    private EvidenceRecordTimestampSource<?> timestampSource;

    /**
     * Cached result of archive data objects validation
     */
    protected List<ReferenceValidation> referenceValidations;

    /**
     * A list of found {@code SignatureScope}s
     */
    private List<SignatureScope> evidenceRecordScopes;

    /**
     * A list of error messages occurred during a structure validation
     */
    protected List<String> structureValidationMessages;

    /** Cached identifier instance */
    private Identifier identifier;

    /**
     * Default constructor
     */
    protected DefaultEvidenceRecord() {
        // empty
    }

    @Override
    public String getFilename() {
        return filename;
    }

    /**
     * Sets the evidence record filename
     *
     * @param filename {@link String}
     */
    public void setFilename(String filename) {
        this.filename = filename;
    }

    @Override
    public List<DSSDocument> getDetachedContents() {
        return detachedContents;
    }

    /**
     * Sets a list of detached documents covered by the reduced HashTree of the Evidence Record
     *
     * @param detachedContents a list of {@link DSSDocument}s
     */
    public void setDetachedContents(final List<DSSDocument> detachedContents) {
        this.detachedContents = detachedContents;
    }

    /**
     * Gets an archive time-stamp sequence
     *
     * @return a list of {@link ArchiveTimeStampChainObject}s
     */
    public List<? extends ArchiveTimeStampChainObject> getArchiveTimeStampSequence() {
        if (archiveTimeStampSequence == null) {
            archiveTimeStampSequence = buildArchiveTimeStampSequence();
        }
        return archiveTimeStampSequence;
    }

    /**
     * Build an archive time-stamp sequence
     *
     * @return a list of ordered {@link ArchiveTimeStampChainObject}s
     */
    protected List<? extends ArchiveTimeStampChainObject> buildArchiveTimeStampSequence() {
        return buildEvidenceRecordParser().parse();
    }

    /**
     * Builds an {@code EvidenceRecordParser} parsing the Evidence Record to a list of DSS DTOs
     *
     * @return {@link EvidenceRecordParser}
     */
    protected abstract EvidenceRecordParser buildEvidenceRecordParser();

    @Override
    public List<ReferenceValidation> getReferenceValidation() {
        if (referenceValidations == null) {
            referenceValidations = validate();
        }
        return referenceValidations;
    }

    /**
     * Performs validation of the evidence record
     *
     * @return a list of {@link ReferenceValidation}s
     */
    protected List<ReferenceValidation> validate() {
        return buildCryptographicEvidenceRecordVerifier().getReferenceValidations();
    }

    /**
     * Builds an instance of {@code EvidenceRecordTimeStampSequenceVerifier}
     * to perform a cryptographic validation of an evidence record
     *
     * @return {@link EvidenceRecordTimeStampSequenceVerifier}
     */
    protected abstract EvidenceRecordTimeStampSequenceVerifier buildCryptographicEvidenceRecordVerifier();

    @Override
    public List<TimestampToken> getTimestamps() {
        return getTimestampSource().getTimestamps();
    }

    /**
     * Gets a Timestamp source which contains ALL timestamps embedded in the evidence record.
     *
     * @return {@code EvidenceRecordTimestampSource}
     */
    public EvidenceRecordTimestampSource<?> getTimestampSource() {
        if (timestampSource == null) {
            timestampSource = buildTimestampSource();
        }
        return timestampSource;
    }

    /**
     * Builds a new instance of an {@code EvidenceRecordTimestampSource}
     *
     * @return {@link EvidenceRecordTimestampSource}
     */
    protected abstract EvidenceRecordTimestampSource<?> buildTimestampSource();

    @Override
    public List<SignatureScope> getEvidenceRecordScopes() {
        if (evidenceRecordScopes == null) {
            evidenceRecordScopes = findEvidenceRecordScopes();
        }
        return evidenceRecordScopes;
    }

    /**
     * Finds signature scopes
     *
     * @return a list of {@link SignatureScope}s
     */
    protected List<SignatureScope> findEvidenceRecordScopes() {
        return new EvidenceRecordScopeFinder().findEvidenceRecordScope(this);
    }

    @Override
    public List<String> getStructureValidationResult() {
        if (Utils.isCollectionEmpty(structureValidationMessages)) {
            structureValidationMessages = validateStructure();
        }
        return structureValidationMessages;
    }

    /**
     * This method is used to verify the structure of the evidence record document
     *
     * @return a list of {@link String} errors when applicable
     */
    public List<String> validateStructure() {
        // not implemented by default
        return Collections.emptyList();
    }

    @Override
    public Identifier getDSSId() {
        if (identifier == null) {
            identifier = new EvidenceRecordIdentifierBuilder(this).build();
        }
        return identifier;
    }

    @Override
    public String getId() {
        return getDSSId().asXmlId();
    }

}