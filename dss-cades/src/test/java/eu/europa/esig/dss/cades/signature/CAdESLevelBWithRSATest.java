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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

@Tag("slow")
class CAdESLevelBWithRSATest extends AbstractCAdESTestSignature {

	private static final String HELLO_WORLD = "Hello World";

	private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
	private CAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	private static Stream<Arguments> data() {

		List<Arguments> args = new ArrayList<>();

		List<DigestAlgorithm> digestAlgos = Arrays.asList(DigestAlgorithm.SHA224, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512,
				DigestAlgorithm.SHA3_224, DigestAlgorithm.SHA3_256, DigestAlgorithm.SHA3_384, DigestAlgorithm.SHA3_512);
		for (DigestAlgorithm digest1 : digestAlgos) {
			for (DigestAlgorithm digest2 : digestAlgos) {
				args.add(Arguments.of(digest1, digest2, EncryptionAlgorithm.RSA));
				args.add(Arguments.of(digest1, digest2, EncryptionAlgorithm.RSASSA_PSS));
			}
		}

		List<DigestAlgorithm> messageDigestAlgos = Arrays.asList(DigestAlgorithm.RIPEMD160, DigestAlgorithm.MD2, DigestAlgorithm.MD5);
		for (DigestAlgorithm digest1 : messageDigestAlgos) {
			args.add(Arguments.of(digest1, digest1, EncryptionAlgorithm.RSA));
			for (DigestAlgorithm digest2 : digestAlgos) {
				args.add(Arguments.of(digest1, digest2, EncryptionAlgorithm.RSA));
			}
		}

		// DigestAlgorithm.WHIRLPOOL
		for (DigestAlgorithm digest : digestAlgos) {
			args.add(Arguments.of(DigestAlgorithm.WHIRLPOOL, digest, EncryptionAlgorithm.RSA));
		}

		// Due to
		// org.bouncycastle.cms.DefaultCMSSignatureEncryptionAlgorithmFinder.findEncryptionAlgorithm(AlgorithmIdentifier)
		List<DigestAlgorithm> digestAlgosWithSha1 = new ArrayList<>(digestAlgos);
		digestAlgosWithSha1.add(DigestAlgorithm.SHA1);
		for (DigestAlgorithm digest : digestAlgosWithSha1) {
			args.add(Arguments.of(DigestAlgorithm.SHA1, digest, EncryptionAlgorithm.RSA));
			args.add(Arguments.of(DigestAlgorithm.SHA1, digest, EncryptionAlgorithm.RSASSA_PSS));
		}

		return args.stream();
	}

	@ParameterizedTest(name = "Combination {index} of message-digest algorithm {0} + digest algorithm {1} + encryption algorithm {2}")
	@MethodSource("data")
	void init(DigestAlgorithm messageDigestAlgo, DigestAlgorithm digestAlgo, EncryptionAlgorithm encryptionAlgorithm) {
		documentToSign = new InMemoryDocument(HELLO_WORLD.getBytes(),
				"BC-CAdES-BpB-att-" + messageDigestAlgo.name() + "-" + digestAlgo.name() + "withRSA" +
						(EncryptionAlgorithm.RSASSA_PSS == encryptionAlgorithm ? "MGF1" : "" ) + ".p7m");

		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.setReferenceDigestAlgorithm(messageDigestAlgo);
		signatureParameters.setDigestAlgorithm(digestAlgo);
		signatureParameters.setEncryptionAlgorithm(encryptionAlgorithm);

		service = new CAdESService(getOfflineCertificateVerifier());

		super.signAndVerify();
	}

	@Override
	public void signAndVerify() {
		// skip
	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
