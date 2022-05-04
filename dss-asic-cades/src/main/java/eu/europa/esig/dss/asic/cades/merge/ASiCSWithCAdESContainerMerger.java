package eu.europa.esig.dss.asic.cades.merge;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.DefaultASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * This class is used to merge ASiC-S with CAdES containers.
 *
 */
public class ASiCSWithCAdESContainerMerger extends AbstractASiCWithCAdESContainerMerger {

    /**
     * Defines rules for filename creation for new ZIP entries (e.g. signature files, etc.)
     */
    protected ASiCWithCAdESFilenameFactory asicFilenameFactory = new DefaultASiCWithCAdESFilenameFactory();

    /**
     * Empty constructor
     */
    ASiCSWithCAdESContainerMerger() {
    }

    /**
     * This constructor is used to create an ASiC-S With CAdES container merger from provided container documents
     *
     * @param containers {@link DSSDocument}s representing containers to be merged
     */
    public ASiCSWithCAdESContainerMerger(DSSDocument... containers) {
        super(containers);
    }

    /**
     * This constructor is used to create an ASiC-S With CAdES from to given {@code ASiCContent}s
     *
     * @param asicContents {@link ASiCContent}s to be merged
     */
    public ASiCSWithCAdESContainerMerger(ASiCContent... asicContents) {
        super(asicContents);
    }

    /**
     * Sets {@code ASiCWithCAdESFilenameFactory} defining a set of rules for naming of newly create ZIP entries,
     * such as signature files.
     *
     * @param asicFilenameFactory {@link ASiCWithCAdESFilenameFactory}
     */
    public void setAsicFilenameFactory(ASiCWithCAdESFilenameFactory asicFilenameFactory) {
        Objects.requireNonNull(asicFilenameFactory, "ASiCWithCAdESFilenameFactory cannot be null!");
        this.asicFilenameFactory = asicFilenameFactory;
    }

    @Override
    public boolean isSupported(DSSDocument container) {
        return super.isSupported(container) && !ASiCUtils.isASiCEContainer(container);
    }

    @Override
    public boolean isSupported(ASiCContent asicContent) {
        return super.isSupported(asicContent) && !ASiCUtils.isASiCEContainer(asicContent);
    }

    @Override
    protected ASiCContainerType getTargetASiCContainerType() {
        return ASiCContainerType.ASiC_S;
    }

    @Override
    protected void ensureContainerContentAllowMerge() {
        if (Arrays.stream(asicContents).allMatch(asicContent -> Utils.isCollectionEmpty(asicContent.getSignatureDocuments())) &&
                Arrays.stream(asicContents).allMatch(asicContent -> Utils.isCollectionEmpty(asicContent.getTimestampDocuments()))) {
            return; // no signatures/timestamps -> can merge
        }

        if (Arrays.stream(asicContents).anyMatch(asicContent -> Utils.collectionSize(asicContent.getSignatureDocuments()) +
                Utils.collectionSize(asicContent.getTimestampDocuments()) > 1)) {
            throw new UnsupportedOperationException("Unable to merge ASiC-S with CAdES containers. " +
                    "One of the containers has more than one signature or timestamp documents!");
        }
        if (Arrays.stream(asicContents).anyMatch(asicContent -> Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments())) &&
                Arrays.stream(asicContents).anyMatch(asicContent -> Utils.isCollectionNotEmpty(asicContent.getTimestampDocuments()))) {
            throw new UnsupportedOperationException("Unable to merge ASiC-S with CAdES containers. " +
                    "A container containing a timestamp file cannot be merged with other signed or timestamped container!");
        }
        if (Arrays.stream(asicContents).filter(asicContent -> Utils.isCollectionNotEmpty(asicContent.getTimestampDocuments())).count() > 1) {
            throw new UnsupportedOperationException("Unable to merge ASiC-S with CAdES containers. " +
                    "Multiple containers contain detached timestamps!");
        }

        Arrays.stream(asicContents).forEach(asicContent -> assertSignatureDocumentNameValid(asicContent.getSignatureDocuments()));
        Arrays.stream(asicContents).forEach(asicContent -> assertTimestampDocumentNameValid(asicContent.getTimestampDocuments()));

        if (Arrays.stream(asicContents).anyMatch(asicContent -> Utils.collectionSize(asicContent.getRootLevelSignedDocuments()) > 1)) {
            throw new UnsupportedOperationException("Unable to merge ASiC-S with CAdES containers. " +
                    "One of the containers has more than one signer documents!");
        }

        if (!checkRootSignerDocumentsNames()) {
            throw new UnsupportedOperationException("Unable to merge ASiC-S with CAdES containers. " +
                    "Signer documents have different names!");
        }
    }

    private void assertSignatureDocumentNameValid(List<DSSDocument> signatureDocuments) {
        if (Utils.isCollectionNotEmpty(signatureDocuments)) {
            for (DSSDocument signatureDocument : signatureDocuments) {
                if (!ASiCUtils.SIGNATURE_P7S.equals(signatureDocument.getName()) ) {
                    throw new UnsupportedOperationException("Unable to merge ASiC-S with CAdES containers. " +
                            "The signature document in one of the containers has invalid naming!");
                }
            }
        }
    }

    private void assertTimestampDocumentNameValid(List<DSSDocument> timestampDocuments) {
        if (Utils.isCollectionNotEmpty(timestampDocuments)) {
            for (DSSDocument tstDocument : timestampDocuments) {
                if (!ASiCUtils.TIMESTAMP_TST.equals(tstDocument.getName())) {
                    throw new UnsupportedOperationException("Unable to merge ASiC-S with CAdES containers. " +
                            "The timestamp document in one of the containers has invalid naming!");
                }
            }
        }
    }

    private boolean checkRootSignerDocumentsNames() {
        String rootSignedDocumentName = null;
        for (ASiCContent asicContent : asicContents) {
            List<DSSDocument> rootLevelSignedDocuments = asicContent.getRootLevelSignedDocuments();
            if (Utils.isCollectionNotEmpty(rootLevelSignedDocuments)) {
                DSSDocument currentSignedDocument = rootLevelSignedDocuments.get(0); // only one shall be present
                if (rootSignedDocumentName == null) {
                    rootSignedDocumentName = currentSignedDocument.getName();
                } else {
                    return rootSignedDocumentName.equals(currentSignedDocument.getName());
                }
            }
        }
        return true;
    }

    @Override
    protected void ensureSignaturesAllowMerge() {
        if (Arrays.stream(asicContents).filter(asicContent ->
                Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments())).count() <= 1) {
            // one of the containers does not contain a signature document. Can merge.
            return;
        }

        List<DSSDocument> allSignatureDocuments = getAllSignatureDocuments(asicContents);
        DSSDocument mergedCMSSignaturesDocument = mergeCmsSignatures(allSignatureDocuments);
        for (ASiCContent asicContent : asicContents) {
            asicContent.setSignatureDocuments(Collections.singletonList(mergedCMSSignaturesDocument));
        }
    }

}
