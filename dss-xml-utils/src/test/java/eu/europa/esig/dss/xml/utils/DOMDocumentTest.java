package eu.europa.esig.dss.xml.utils;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DOMDocumentTest {

    private static final String XML_CONTENT = "<el id=\"signedData\">Text</el>";

    @Test
    void test() {
        DOMDocument doc = new DOMDocument(DomUtils.buildDOM(XML_CONTENT));
        assertNotNull(doc);
        assertNotNull(doc.getNode());
        assertEquals(MimeTypeEnum.XML, doc.getMimeType());
        assertNull(doc.getName());
        assertNotNull(doc.getBytes());
        assertNotNull(doc.getDigestValue(DigestAlgorithm.SHA256));

        doc = new DOMDocument(DomUtils.buildDOM(XML_CONTENT), "doc.xml");
        assertNotNull(doc);
        assertNotNull(doc.getNode());
        assertEquals(MimeTypeEnum.XML, doc.getMimeType());
        assertEquals("doc.xml", doc.getName());
        assertNotNull(doc.getBytes());
        assertNotNull(doc.getDigestValue(DigestAlgorithm.SHA256));
    }

    @Test
    void testSetter() {
        DOMDocument doc = new DOMDocument(DomUtils.buildDOM(XML_CONTENT));
        doc.setName("doc.xml");
        doc.setMimeType(MimeTypeEnum.TEXT);
        assertEquals(MimeTypeEnum.TEXT, doc.getMimeType());
        assertEquals("doc.xml", doc.getName());
        assertNotNull(doc.getDigestValue(DigestAlgorithm.SHA256));
    }

    @Test
    void persistenceTest() {
        final Set<DSSDocument> hashSet = new HashSet<>();

        DSSDocument document = getPersistenceTestDocument();
        hashSet.add(document);
        assertTrue(hashSet.contains(document));

        Digest digest = document.getDigest(DigestAlgorithm.SHA256);
        assertNotNull(digest);

        assertTrue(hashSet.contains(document));
        assertTrue(hashSet.contains(getPersistenceTestDocument()));

        for (DSSDocument altDocument : getPersistenceTestAlternativeDocuments()) {
            assertFalse(hashSet.contains(altDocument));
        }
    }

    private DSSDocument getPersistenceTestDocument() {
        return new DOMDocument(DomUtils.buildDOM(XML_CONTENT), "xmlDoc");
    }

    private List<DSSDocument> getPersistenceTestAlternativeDocuments() {
        return Arrays.asList(
                new DOMDocument(DomUtils.buildDOM(XML_CONTENT)),
                new DOMDocument(DomUtils.buildDOM(XML_CONTENT), "wrong name"),
                new DOMDocument(DomUtils.buildDOM("<el id=\"signedData\">Alt Text</el>"))
        );
    }

}
