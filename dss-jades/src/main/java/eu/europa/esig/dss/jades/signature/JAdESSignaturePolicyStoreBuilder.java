package eu.europa.esig.dss.jades.signature;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JWSJsonSerializationGenerator;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationParser;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.jades.validation.JAdESEtsiUHeader;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignaturePolicy;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidator;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidatorLoader;

/**
 * The builder used to incorporate a {@code SignaturePolicyStore} to a
 * JAdESSignature document
 *
 */
public class JAdESSignaturePolicyStoreBuilder extends JAdESExtensionBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESSignaturePolicyStoreBuilder.class);

	/**
	 * Adds {@code signaturePolicyStore} to signatures inside the {@code document}
	 * 
	 * @param document             {@link DSSDocument} containing JAdES signatures
	 *                             to extend with a {@link SignaturePolicyStore}
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to incorporate
	 * @param base64UrlInstance    TRUE if the signature policy store shall be
	 *                             incorporated as a base64url encoded component of
	 *                             the 'etsiU' header, FALSE if it will be
	 *                             incorporated in its clear JSON representation
	 * @return {@link DSSDocument} containing signatures with
	 *         {@code signaturePolicyStore}
	 */
	public DSSDocument addSignaturePolicyStore(DSSDocument document, SignaturePolicyStore signaturePolicyStore, boolean base64UrlInstance) {
		Objects.requireNonNull(signaturePolicyStore, "SignaturePolicyStore must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSpDocSpecification(), "SpDocSpecification must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSpDocSpecification().getId(), "ID (OID or URI) for SpDocSpecification must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSignaturePolicyContent(), "Signature policy content must be provided");

		JWSJsonSerializationParser parser = new JWSJsonSerializationParser(document);
		JWSJsonSerializationObject jwsJsonSerializationObject = parser.parse();

		if (jwsJsonSerializationObject == null || Utils.isCollectionEmpty(jwsJsonSerializationObject.getSignatures())) {
			throw new DSSException("There is no signature to extend!");
		}

		for (JWS signature : jwsJsonSerializationObject.getSignatures()) {
			assertExtensionPossible(signature, base64UrlInstance);

			JAdESSignature jadesSignature = new JAdESSignature(signature);
			extendSignature(jadesSignature, signaturePolicyStore, base64UrlInstance);
		}

		JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(jwsJsonSerializationObject,
				jwsJsonSerializationObject.getJWSSerializationType());
		return generator.generate();
	}

	private void extendSignature(JAdESSignature jadesSignature, SignaturePolicyStore signaturePolicyStore, boolean base64UrlInstance) {
		SignaturePolicy policyId = jadesSignature.getSignaturePolicy();
		if (policyId != null && policyId.getDigest() != null) {
			Digest expectedDigest = policyId.getDigest();
			policyId.setPolicyContent(signaturePolicyStore.getSignaturePolicyContent());
			
			SignaturePolicyValidator validator = new SignaturePolicyValidatorLoader(policyId).loadValidator();
			Digest computedDigest = validator.getComputedDigest(expectedDigest.getAlgorithm());
			if (expectedDigest.equals(computedDigest)) {

				Map<String, Object> sigPolicyStoreParams = new LinkedHashMap<>();
				sigPolicyStoreParams.put(JAdESHeaderParameterNames.SIG_POL_DOC,
						Utils.toBase64(DSSUtils.toByteArray(signaturePolicyStore.getSignaturePolicyContent())));

				SpDocSpecification spDocSpecification = signaturePolicyStore.getSpDocSpecification();
				JsonObject oidObject = DSSJsonUtils.getOidObject(spDocSpecification.getId(), spDocSpecification.getDescription(), 
						spDocSpecification.getDocumentationReferences());
				sigPolicyStoreParams.put(JAdESHeaderParameterNames.SP_DSPEC, oidObject);

				JAdESEtsiUHeader etsiUHeader = jadesSignature.getEtsiUHeader();
				etsiUHeader.addComponent(jadesSignature.getJws(), JAdESHeaderParameterNames.SIG_PST,
						sigPolicyStoreParams, base64UrlInstance);

			} else {
				LOG.warn("Signature policy's digest doesn't match the document {} for signature {}", expectedDigest, jadesSignature.getId());
			}
		} else {
			LOG.warn("No SignaturePolicyIdentifier '{}' found for a signature with id '{}'!",
					JAdESHeaderParameterNames.SIG_PID, jadesSignature.getId());
		}
	}

}
