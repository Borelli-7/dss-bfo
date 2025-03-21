/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.xml.utils.SantuarioInitializer;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Attr;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DetachedSignatureResolverTest {

	static {
		SantuarioInitializer.init();
	}

	@Test
	void nullAttribute() {
		Exception exception = assertThrows(ResourceResolverException.class, () -> {
			DetachedSignatureResolver resolver = new DetachedSignatureResolver(Collections.emptyList(), DigestAlgorithm.SHA256);

			Attr attr = null;

			// Empty
			ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
			assertTrue(resolver.engineCanResolveURI(context));

			// will throw ResourceResolverException
			resolver.engineResolveURI(context);
		});
		assertEquals("Unable to find document (detached signature)", exception.getMessage());
	}

	@Test
	void nullListAndNullAttribute() {
		Exception exception = assertThrows(ResourceResolverException.class, () -> {
			DetachedSignatureResolver resolver = new DetachedSignatureResolver(null, DigestAlgorithm.SHA256);

			Attr attr = null;

			// Empty
			ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
			assertTrue(resolver.engineCanResolveURI(context));

			// will throw ResourceResolverException
			resolver.engineResolveURI(context);
		});
		assertEquals("Unable to find document (detached signature)", exception.getMessage());
	}

	@Test
	void nullAttributeOneDoc() throws ResourceResolverException {
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(Arrays.asList(new InMemoryDocument(new byte[] { 1, 2, 3 })),
				DigestAlgorithm.SHA256);

		Attr attr = null;

		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertTrue(resolver.engineCanResolveURI(context));

		assertNotNull(resolver.engineResolveURI(context));
	}

	@Test
	void nullAttributeTwoDocs() {
		Exception exception = assertThrows(ResourceResolverException.class, () -> {
			DetachedSignatureResolver resolver = new DetachedSignatureResolver(
					Arrays.asList(new InMemoryDocument(new byte[] { 1, 2, 3 }), new InMemoryDocument(new byte[] { 2, 3 })), DigestAlgorithm.SHA256);

			Attr attr = null;

			ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
			assertTrue(resolver.engineCanResolveURI(context));

			// 2 docs + no name -> exception
			resolver.engineResolveURI(context);
		});
		assertEquals("Unable to find document (detached signature)", exception.getMessage());
	}

	@Test
	void emptyAttribute() {
		Exception exception = assertThrows(ResourceResolverException.class, () -> {
			DetachedSignatureResolver resolver = new DetachedSignatureResolver(Collections.emptyList(), DigestAlgorithm.SHA256);

			Attr attr = mock(Attr.class);

			// Empty
			when(attr.getNodeValue()).thenReturn("");
			ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
			assertFalse(resolver.engineCanResolveURI(context));

			// will throw ResourceResolverException
			resolver.engineResolveURI(context);
		});
		assertEquals("Unable to find document (detached signature)", exception.getMessage());
	}

	@Test
	void attributeIsAnchor() {
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(Collections.emptyList(), DigestAlgorithm.SHA256);

		Attr attr = mock(Attr.class);

		when(attr.getNodeValue()).thenReturn("#id_tag");
		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertFalse(resolver.engineCanResolveURI(context));
	}

	@Test
	void documentNameWithEmptyList() {
		Exception exception = assertThrows(ResourceResolverException.class, () -> {
			DetachedSignatureResolver resolver = new DetachedSignatureResolver(Collections.emptyList(), DigestAlgorithm.SHA256);

			Attr attr = mock(Attr.class);

			// document name + no document in the list
			when(attr.getNodeValue()).thenReturn("sample.xml");
			ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
			assertTrue(resolver.engineCanResolveURI(context));

			// will throw ResourceResolverException
			resolver.engineResolveURI(context);
		});
		assertEquals("Unable to find document (detached signature)", exception.getMessage());
	}

	@Test
	void engineCanResolveURIWithWrongDocumentNameInList() {
		Exception exception = assertThrows(ResourceResolverException.class, () -> {
			DetachedSignatureResolver resolver = new DetachedSignatureResolver(
					Arrays.asList(new InMemoryDocument(new byte[] { 1, 2, 3 }, "toto.xml", MimeTypeEnum.XML)),
					DigestAlgorithm.SHA256);

			Attr attr = mock(Attr.class);

			// document name + wrong document in the list
			when(attr.getNodeValue()).thenReturn("sample.xml");
			ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
			assertTrue(resolver.engineCanResolveURI(context));

			// doc not found -> exception
			resolver.engineResolveURI(context);
		});
		assertEquals("Unable to find document 'sample.xml' (detached signature)", exception.getMessage());
	}

	@Test
	void engineCanResolveURIWithDocumentNoNameInList() throws ResourceResolverException {
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(Arrays.asList(new InMemoryDocument(new byte[] { 1, 2, 3 })),
				DigestAlgorithm.SHA256);

		Attr attr = mock(Attr.class);

		// document name + only one document
		when(attr.getNodeValue()).thenReturn("sample.xml");
		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertTrue(resolver.engineCanResolveURI(context));

		assertNotNull(resolver.engineResolveURI(context));
	}

	@Test
	void engineCanResolveURIWithDocumentNameInList() throws ResourceResolverException {
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(
				Arrays.asList(new InMemoryDocument(new byte[] { 1, 2, 3 }, "sample.xml", MimeTypeEnum.XML)),
				DigestAlgorithm.SHA256);

		Attr attr = mock(Attr.class);

		when(attr.getNodeValue()).thenReturn("sample.xml");
		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertTrue(resolver.engineCanResolveURI(context));

		assertNotNull(resolver.engineResolveURI(context));
	}

	@Test
	void engineCanResolveURIWithDocumentNameInListOfMultiples() throws ResourceResolverException {
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(
				Arrays.asList(new InMemoryDocument(new byte[] { 1, 2, 3 }, "sample.xml", MimeTypeEnum.XML),
				new InMemoryDocument(new byte[] { 2, 3 }, "sample2.xml", MimeTypeEnum.XML)), DigestAlgorithm.SHA256);

		Attr attr = mock(Attr.class);

		when(attr.getNodeValue()).thenReturn("sample.xml");
		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertTrue(resolver.engineCanResolveURI(context));

		assertNotNull(resolver.engineResolveURI(context));
	}

	@Test
	void engineCanResolveURIWithDigestDocument() throws ResourceResolverException {
		DigestDocument doc = new DigestDocument(DigestAlgorithm.SHA256, "abcdef");
		doc.setName("sample.xml");
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(Arrays.asList(doc), DigestAlgorithm.SHA256);

		Attr attr = mock(Attr.class);

		when(attr.getNodeValue()).thenReturn("sample.xml");
		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertTrue(resolver.engineCanResolveURI(context));

		assertNotNull(resolver.engineResolveURI(context));
	}

	@Test
	void engineCanResolveURIWithDigestDocumentSpecialChar() throws ResourceResolverException {
		DigestDocument doc = new DigestDocument(DigestAlgorithm.SHA256, "abcdef");
		doc.setName("hello+world.xml");
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(Arrays.asList(doc), DigestAlgorithm.SHA256);

		Attr attr = mock(Attr.class);

		when(attr.getNodeValue()).thenReturn("hello%2Bworld.xml");
		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertTrue(resolver.engineCanResolveURI(context));

		assertNotNull(resolver.engineResolveURI(context));
	}

	@Test
	void engineCanResolveURIWithDigestDocumentNoName() throws ResourceResolverException {
		DigestDocument doc = new DigestDocument(DigestAlgorithm.SHA256, "abcdef");
		// doc.setName("sample.xml");
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(Arrays.asList(doc), DigestAlgorithm.SHA256);

		Attr attr = mock(Attr.class);

		when(attr.getNodeValue()).thenReturn("sample.xml");
		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertTrue(resolver.engineCanResolveURI(context));

		assertNotNull(resolver.engineResolveURI(context));
	}

}
