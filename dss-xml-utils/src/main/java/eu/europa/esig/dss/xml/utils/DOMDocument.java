package eu.europa.esig.dss.xml.utils;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.CommonDocument;
import org.w3c.dom.Node;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Objects;

/**
 * This class allows handling of an {@code org.w3c.dom.Node} as a {@code eu.europa.esig.dss.model.DSSDocument}.
 * The class handles the {@code Node} in memory, and reads its data only on request.
 * This class uses a {@code eu.europa.esig.dss.model.InMemoryDocument} for internal processing of
 * the cached {@code org.w3c.dom.Node}'s content.
 *
 */
public class DOMDocument extends CommonDocument {

    private static final long serialVersionUID = -4382025786481298319L;

    /** The Node defining the document */
    private final Node node;

    /** Cached bytes of the Element's content */
    private byte[] bytes;

    /**
     * Default constructor to create a {@code DOMDocument} from an {@code org.w3c.dom.Element}.
     * NOTE: Uses a {@code MimeTypeEnum.XML} MimeType by default.
     *
     * @param node
     *            {@link org.w3c.dom.Node} to create a document from
     */
    public DOMDocument(final Node node) {
        this(node, null);
    }

    /**
     * Constructor to create a {@code DOMDocument} with name provided.
     * NOTE: Uses a {@code MimeTypeEnum.XML} MimeType by default.
     *
     * @param node
     *            {@link org.w3c.dom.Node} to create a document from
     * @param name
     *            {@link String} the file name
     */
    public DOMDocument(final Node node, final String name) {
        Objects.requireNonNull(node, "Element cannot be null");
        this.node = node;
        this.name = name;
        this.mimeType = MimeTypeEnum.XML;
    }

    /**
     * Gets the Node used to define the document
     *
     * @return {@link Node}
     */
    public Node getNode() {
        return node;
    }

    @Override
    public InputStream openStream() {
        return new ByteArrayInputStream(getBytes());
    }

    /**
     * Gets cached binary array as the result of the Element serialization
     *
     * @return byte array
     */
    protected byte[] getBytes() {
        if (bytes == null) {
            bytes = DomUtils.serializeNode(node);
        }
        return bytes;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;

        DOMDocument that = (DOMDocument) o;
        return Arrays.equals(getBytes(), that.getBytes());
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + Arrays.hashCode(getBytes());
        return result;
    }

}
