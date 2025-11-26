package eu.europa.esig.dss.validation.qwac;

import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class LinkHeaderParserTest {

    private static LinkHeaderParser parser;

    @BeforeAll
    static void init() {
        parser = new LinkHeaderParser();
    }

    @Test
    void test() {
        List<LinkHeaderParser.LinkHeader> linkHeader = parser.parse("<http://example.com/TheBook/chapter2>; rel=\"previous\"; title=\"previous chapter\"");
        assertEquals(1, Utils.collectionSize(linkHeader));
        assertEquals("http://example.com/TheBook/chapter2", linkHeader.get(0).getUrl());
        assertEquals("previous", linkHeader.get(0).getAttributes().get("rel"));
        assertEquals("previous chapter", linkHeader.get(0).getAttributes().get("title"));
    }

    @Test
    void emptyLinkTest() {
        List<LinkHeaderParser.LinkHeader> linkHeader = parser.parse("</>; rel=\"http://example.net/foo\"");
        assertEquals(1, Utils.collectionSize(linkHeader));
        assertEquals("/", linkHeader.get(0).getUrl());
        assertEquals("http://example.net/foo", linkHeader.get(0).getAttributes().get("rel"));
    }

    @Test
    void emptyAttrsTest() {
        List<LinkHeaderParser.LinkHeader> linkHeader = parser.parse("<http://example.net>");
        assertEquals(1, Utils.collectionSize(linkHeader));
        assertEquals("http://example.net", linkHeader.get(0).getUrl());
        assertEquals(0, linkHeader.get(0).getAttributes().size());
    }

    @Test
    void multipleLinksTest() {
        List<LinkHeaderParser.LinkHeader> linkHeader = parser.parse("<https://example.org/>; rel=\"start\", <https://example.org/index>; rel=\"index\"");
        assertEquals(2, Utils.collectionSize(linkHeader));
        assertEquals("https://example.org/", linkHeader.get(0).getUrl());
        assertEquals("start", linkHeader.get(0).getAttributes().get("rel"));
        assertEquals("https://example.org/index", linkHeader.get(1).getUrl());
        assertEquals("index", linkHeader.get(1).getAttributes().get("rel"));
    }

    @Test
    void nullTest() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> parser.parse(null));
        assertEquals("Link header cannot be null or empty", exception.getMessage());

        exception = assertThrows(IllegalArgumentException.class, () -> parser.parse(""));
        assertEquals("Link header cannot be null or empty", exception.getMessage());

        exception = assertThrows(IllegalArgumentException.class, () -> parser.parse(" "));
        assertEquals("Link header cannot be null or empty", exception.getMessage());
    }

    @Test
    void noLinkTest() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> parser.parse("rel=\"start\""));
        assertEquals("Link entry must start with '<': rel=\"start\"", exception.getMessage());
    }

}
