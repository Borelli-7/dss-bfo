package eu.europa.esig.dss.jades.signature;

import java.util.Collections;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Set;

import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESArchiveTimestampType;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.validation.ValidationDataForInclusion;

public class JAdESLevelBaselineLTA extends JAdESLevelBaselineLT {

	public JAdESLevelBaselineLTA(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}
	
	@Override
	protected void extendSignature(JAdESSignature jadesSignature, JAdESSignatureParameters params) {
		super.extendSignature(jadesSignature, params);
		
		assertExtendSignatureToLTAPossible(jadesSignature, params);
		checkSignatureIntegrity(jadesSignature);
		
		List<Object> unsignedProperties = getUnsignedProperties(jadesSignature);
		
		if (jadesSignature.hasLTAProfile()) {
			// must be executed before data removing
			final ValidationContext validationContext = jadesSignature.getSignatureValidationContext(certificateVerifier);
			removeLastTimestampValidationData(unsignedProperties);
			
			final ValidationDataForInclusion validationDataForInclusion = getValidationDataForInclusion(jadesSignature, validationContext);
			addTstVd(validationDataForInclusion, unsignedProperties);
		}
		
		TimestampBinary timestampBinary = getArchiveTimestamp(jadesSignature, params);
		addArcTst(timestampBinary, unsignedProperties, params.getArchiveTimestampParameters());
		
	}
	@SuppressWarnings("unchecked")
	private void removeLastTimestampValidationData(List<Object> unsignedProperties) {
		ListIterator<Object> iterator = unsignedProperties.listIterator(unsignedProperties.size());
		while (iterator.hasPrevious()) {
			Map<String, Object> unsignedProperty = (Map<String, Object>) iterator.previous();
			Object tstVd = unsignedProperty.get(JAdESHeaderParameterNames.TST_VD);
			if (tstVd != null) {
				iterator.remove();
				return;
			}
		}
	}

	@SuppressWarnings("unchecked")
	protected void addTstVd(final ValidationDataForInclusion validationDataForInclusion, List<Object> unsignedProperties) {
		Set<CertificateToken> certificateTokens = validationDataForInclusion.getCertificateTokens();
		List<CRLToken> crlTokens = validationDataForInclusion.getCrlTokens();
		List<OCSPToken> ocspTokens = validationDataForInclusion.getOcspTokens();
		
		if (Utils.isCollectionEmpty(certificateTokens) && Utils.isCollectionEmpty(crlTokens) && Utils.isCollectionEmpty(ocspTokens)) {
			// nothing to add
			return;
		}
		
		JSONObject tstVd = new JSONObject();
		
		if (Utils.isCollectionNotEmpty(certificateTokens)) {
			JSONArray xVals = getXVals(certificateTokens);
			tstVd.put(JAdESHeaderParameterNames.CERT_VALS, xVals);
		}
		
		if (Utils.isCollectionNotEmpty(crlTokens) || Utils.isCollectionNotEmpty(ocspTokens)) {
			JSONObject rVals = getRVals(crlTokens, ocspTokens);
			tstVd.put(JAdESHeaderParameterNames.REV_VALS, rVals);
		}
		
		/* 
		 * If the onSdo member is absent or it  is present and its value is set to "false", 
		 * then it shall indicate that the electronic time-stamp whose validation material 
		 * contains the tstVd JSON object, does not time-stamp the signed data objects.
		 */
		
		// Content tst'data is included on LT-level, therefore should not be included on LTA
		
		JSONObject tstVdItem = new JSONObject();
		tstVdItem.put(JAdESHeaderParameterNames.TST_VD, tstVd);
		
		unsignedProperties.add(tstVdItem);
		
	}
	
	private TimestampBinary getArchiveTimestamp(JAdESSignature jadesSignature, JAdESSignatureParameters params) {
		JAdESTimestampParameters archiveTimestampParameters = params.getArchiveTimestampParameters();
		DigestAlgorithm digestAlgorithmForTimestampRequest = archiveTimestampParameters.getDigestAlgorithm();

		// TODO : Support canonicalization
		String canonicalizationMethod = archiveTimestampParameters.getCanonicalizationMethod();
		JAdESArchiveTimestampType jadesArchiveTimestampType = archiveTimestampParameters.getArchiveTimestampType();
		
		byte[] messageImprint = jadesSignature.getTimestampSource().getArchiveTimestampData(canonicalizationMethod, jadesArchiveTimestampType);
		
		byte[] digest = DSSUtils.digest(digestAlgorithmForTimestampRequest, messageImprint);
		return tspSource.getTimeStampResponse(digestAlgorithmForTimestampRequest, digest);
	}

	@SuppressWarnings("unchecked")
	protected void addArcTst(TimestampBinary timestampBinary, List<Object> unsignedProperties, JAdESTimestampParameters params) {
		JSONObject arcTst = new JSONObject();
		
		String canonicalizationMethod = params.getCanonicalizationMethod();
		JAdESArchiveTimestampType jadesArchiveTimestampType = params.getArchiveTimestampType();

		JsonObject tstContainer = JAdESUtils.getTstContainer(Collections.singletonList(timestampBinary), canonicalizationMethod);
		arcTst.put(JAdESHeaderParameterNames.TST_CONTAINER, tstContainer);
		
		// all data is timestamped
		arcTst.put(JAdESHeaderParameterNames.TIMESTAMPED, jadesArchiveTimestampType.getValue());
		
		JSONObject arcTstItem = new JSONObject();
		arcTstItem.put(JAdESHeaderParameterNames.ARC_TST, arcTst);
		
		unsignedProperties.add(arcTstItem);
	}

	/**
	 * Checks if the extension is possible.
	 */
	private void assertExtendSignatureToLTAPossible(JAdESSignature jadesSignature, JAdESSignatureParameters params) {
		final SignatureLevel signatureLevel = params.getSignatureLevel();
		JAdESTimestampParameters archiveTimestampParameters = params.getArchiveTimestampParameters();
		JAdESArchiveTimestampType archiveTimestampType = archiveTimestampParameters.getArchiveTimestampType();
		if (SignatureLevel.JAdES_BASELINE_LTA.equals(signatureLevel) && 
				JAdESArchiveTimestampType.TIMESTAMPED_PREVIOUS_ARC_TST.equals(archiveTimestampType) && !jadesSignature.hasLTAProfile()) {
			final String exceptionMessage = "Cannot extend the signature. The signature shall contain an 'arcTst' for extension with"
					+ "'previousArcTst' archive timestamp!";
			throw new DSSException(exceptionMessage);
		}
	}

}
