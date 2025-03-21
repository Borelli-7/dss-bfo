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
package eu.europa.esig.asic.manifest;

import eu.europa.esig.xmldsig.jaxb.SignatureType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.UnmarshalException;
import jakarta.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import java.io.File;
import java.io.StringReader;
import java.io.StringWriter;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASiCManifestUtilsTest {
	
	private static ASiCManifestUtils asicManifestUtils;
	
	@BeforeAll
	static void init() {
		asicManifestUtils = ASiCManifestUtils.getInstance();
	}

	@Test
	@SuppressWarnings("unchecked")
	void test() throws JAXBException, SAXException {

		File xmldsigFile = new File("src/test/resources/ASiCManifest.xml");

		JAXBContext jc = asicManifestUtils.getJAXBContext();
		assertNotNull(jc);

		Schema schema = asicManifestUtils.getSchema();
		assertNotNull(schema);

		Unmarshaller unmarshaller = jc.createUnmarshaller();
		unmarshaller.setSchema(schema);

		JAXBElement<SignatureType> unmarshalled = (JAXBElement<SignatureType>) unmarshaller.unmarshal(xmldsigFile);
		assertNotNull(unmarshalled);

		Marshaller marshaller = jc.createMarshaller();
		marshaller.setSchema(schema);

		StringWriter sw = new StringWriter();
		marshaller.marshal(unmarshalled, sw);

		String xadesString = sw.toString();

		JAXBElement<SignatureType> unmarshalled2 = (JAXBElement<SignatureType>) unmarshaller.unmarshal(new StringReader(xadesString));
		assertNotNull(unmarshalled2);
	}
	
	@Test
	void testInvalidFile() throws JAXBException, SAXException {

		File xmldsigFile = new File("src/test/resources/ASiCManifestInvalid.xml");

		JAXBContext jc = asicManifestUtils.getJAXBContext();
		assertNotNull(jc);

		Schema schema = asicManifestUtils.getSchema();
		assertNotNull(schema);
		
		Unmarshaller unmarshaller = jc.createUnmarshaller();
		unmarshaller.setSchema(schema);

		assertThrows(UnmarshalException.class, () -> unmarshaller.unmarshal(xmldsigFile));
	}

	@Test
	void getSchemaASiCManifest() throws SAXException {
		assertNotNull(asicManifestUtils.getSchema());
		// cached
		assertNotNull(asicManifestUtils.getSchema());
	}
}
