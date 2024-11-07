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
package eu.europa.esig.dss.jades.extension;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JWSConverter;
import eu.europa.esig.dss.jades.signature.AbstractJAdESTestSignature;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JAdESExtensionLTClearToLTATest extends AbstractJAdESTestSignature {

	private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
	private DSSDocument documentToSign;
	private JAdESSignatureParameters signatureParameters;

	@BeforeEach
	void init() throws Exception {
		service = new JAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		documentToSign = new FileDocument(new File("src/test/resources/sample.json"));
		signatureParameters = new JAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LT);
		signatureParameters.setBase64UrlEncodedEtsiUComponents(false);
	}

	@Override
	protected DSSDocument sign() {
		DSSDocument signedDocument = super.sign();

		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LTA);

		Exception exception = assertThrows(IllegalInputException.class,
				() -> service.extendDocument(signedDocument, signatureParameters));
		assertEquals("Unable to extend JAdES-LTA level. Clear 'etsiU' incorporation requires a canonicalization method!",
				exception.getMessage());

		JAdESTimestampParameters archiveTimestampParameters = signatureParameters.getArchiveTimestampParameters();
		exception = assertThrows(UnsupportedOperationException.class, () -> archiveTimestampParameters.setCanonicalizationMethod("c14n"));
		assertEquals("Canonicalization is not supported in the current version.", exception.getMessage());

		signatureParameters.setBase64UrlEncodedEtsiUComponents(true);

		exception = assertThrows(IllegalInputException.class, () -> service.extendDocument(signedDocument, signatureParameters));
		assertEquals("Extension is not possible! The encoding of 'etsiU' "
				+ "components shall match! Use jadesSignatureParameters.setBase64UrlEncodedEtsiUComponents(false)",
				exception.getMessage());

		DSSDocument convertedDocument = JWSConverter.fromEtsiUWithClearJsonToBase64UrlIncorporation(signedDocument);

		DSSDocument extendedDocument = service.extendDocument(convertedDocument, signatureParameters);
		assertNotNull(extendedDocument);
		return extendedDocument;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
