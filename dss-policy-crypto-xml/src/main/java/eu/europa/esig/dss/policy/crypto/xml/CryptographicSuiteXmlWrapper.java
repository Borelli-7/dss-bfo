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
package eu.europa.esig.dss.policy.crypto.xml;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.policy.Abstract19322CryptographicSuite;
import eu.europa.esig.dss.model.policy.SignatureAlgorithmWithMinKeySize;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.AlgorithmIdentifierType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.AlgorithmType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.EvaluationType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.ParameterType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.PolicyNameType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.SecuritySuitabilityPolicyType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.ValidityType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.datatype.XMLGregorianCalendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/**
 * This class wraps an ETSI TS 119 312/322 XML cryptographic suite policy
 *
 */
public class CryptographicSuiteXmlWrapper extends Abstract19322CryptographicSuite {

    private static final Logger LOG = LoggerFactory.getLogger(CryptographicSuiteXmlWrapper.class);

    /** Wrapped SecuritySuitabilityPolicyType */
    private final SecuritySuitabilityPolicyType securitySuitabilityPolicy;

    /**
     * Default constructor
     *
     * @param securitySuitabilityPolicy {@link SecuritySuitabilityPolicyType}
     */
    public CryptographicSuiteXmlWrapper(final SecuritySuitabilityPolicyType securitySuitabilityPolicy) {
        Objects.requireNonNull(securitySuitabilityPolicy, "securitySuitabilityPolicy cannot be null!");
        this.securitySuitabilityPolicy = securitySuitabilityPolicy;
    }

    @Override
    public String getPolicyName() {
        PolicyNameType policyName = securitySuitabilityPolicy.getPolicyName();
        if (policyName != null) {
            return policyName.getName();
        }
        return null;
    }

    @Override
    protected Map<DigestAlgorithm, Date> buildAcceptableDigestAlgorithmsWithExpirationDates() {
        final Map<DigestAlgorithm, Date> digestAlgorithmsMap = new LinkedHashMap<>();
        for (AlgorithmType algorithmType : securitySuitabilityPolicy.getAlgorithm()) {
            AlgorithmIdentifierType algorithmIdentifier = algorithmType.getAlgorithmIdentifier();
            DigestAlgorithm digestAlgorithm = getDigestAlgorithm(algorithmIdentifier);
            if (digestAlgorithm == null) {
                continue;
            }

            Date endDate = getDigestAlgorithmEndDate(algorithmType.getEvaluation());
            if (digestAlgorithmsMap.containsKey(digestAlgorithm)) {
                Date currentEndDate = digestAlgorithmsMap.get(digestAlgorithm);
                if (currentEndDate == null || (endDate != null && currentEndDate.after(endDate))) {
                    endDate = currentEndDate;
                }
            }
            digestAlgorithmsMap.put(digestAlgorithm, endDate);

        }
        return digestAlgorithmsMap;
    }
    
    private DigestAlgorithm getDigestAlgorithm(AlgorithmIdentifierType algorithmIdentifier) {
        if (algorithmIdentifier == null) {
            return null;
        }
        // NOTE: Name is not evaluated, it is not supposed to be machine-processable
        List<String> objectIdentifiers = algorithmIdentifier.getObjectIdentifier();
        if (objectIdentifiers != null && !objectIdentifiers.isEmpty()) {
            for (String oid : objectIdentifiers) {
                try {
                    // first come, first served policy
                    return DigestAlgorithm.forOID(oid);
                } catch (IllegalArgumentException e) {
                    // continue silently
                }
            }
        }
        // optional
        List<String> uris = algorithmIdentifier.getURI();
        if (uris != null && !uris.isEmpty()) {
            for (String uri : uris) {
                try {
                    return DigestAlgorithm.forXML(uri);
                } catch (IllegalArgumentException e) {
                    // continue silently
                }
            }
        }
        return null;
    }

    private Date getDigestAlgorithmEndDate(List<EvaluationType> evaluations) {
        if (evaluations == null || evaluations.isEmpty()) {
            return null;
        }
        Date latestEndDate = null;
        for (EvaluationType evaluation : evaluations) {
            ValidityType validity = evaluation.getValidity();
            if (validity == null) {
                continue;
            }

            Date endDate = getValidityEndDate(validity);
            if (endDate == null) {
                // No EndDate -> consider as a still valid algorithm
                return null;
            } else {
                if (latestEndDate == null || latestEndDate.before(endDate)) {
                    latestEndDate = endDate;
                }
            }
        }
        return latestEndDate;
    }

    private Date getValidityEndDate(ValidityType validity) {
        if (validity.getStart() != null) {
            LOG.debug("The Start date is not supported. The values has been skipped.");
        }
        if (validity.getEnd() != null) {
            XMLGregorianCalendar end = validity.getEnd();
            return end.toGregorianCalendar().getTime();
        }
        return null;
    }

    @Override
    protected Map<SignatureAlgorithmWithMinKeySize, Date> buildAcceptableSignatureAlgorithmsWithExpirationDates() {
        final Map<SignatureAlgorithm, TreeMap<Integer, Date>> signatureAlgorithmWithKeySizesMap = new LinkedHashMap<>();
        final Set<SignatureAlgorithm> explicitlyDefinedSignatureAlgorithms = new HashSet<>();

        // Step 1. Find all entries matching the SignatureAlgorithm definition
        for (AlgorithmType algorithmType : securitySuitabilityPolicy.getAlgorithm()) {
            AlgorithmIdentifierType algorithmIdentifier = algorithmType.getAlgorithmIdentifier();
            SignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm(algorithmIdentifier);
            if (signatureAlgorithm == null) {
                continue;
            }

            TreeMap<Integer, Date> keySizeMap = signatureAlgorithmWithKeySizesMap.getOrDefault(signatureAlgorithm, new TreeMap<>());
            Map<Integer, Date> endDatesMap = getSignatureAlgorithmKeySizeEndDates(signatureAlgorithm, algorithmType.getEvaluation());
            populateKeySizeMap(keySizeMap, endDatesMap);

            explicitlyDefinedSignatureAlgorithms.add(signatureAlgorithm);
            signatureAlgorithmWithKeySizesMap.put(signatureAlgorithm, keySizeMap);
        }

        // Step 2a. Extract supported digest algorithms for mapping
        Map<DigestAlgorithm, Date> digestAlgorithmsWithExpirationDates = getAcceptableDigestAlgorithmsWithExpirationDates();

        // Step 2b. Process encryption algorithms defined independently
        for (AlgorithmType algorithmType : securitySuitabilityPolicy.getAlgorithm()) {
            AlgorithmIdentifierType algorithmIdentifier = algorithmType.getAlgorithmIdentifier();
            EncryptionAlgorithm encryptionAlgorithm = getEncryptionAlgorithm(algorithmIdentifier);
            if (encryptionAlgorithm == null) {
                continue;
            }

            for (Map.Entry<DigestAlgorithm, Date> digestAlgorithmWithDateEntry : digestAlgorithmsWithExpirationDates.entrySet()) {
                SignatureAlgorithm signatureAlgorithm = findSignatureAlgorithm(encryptionAlgorithm, digestAlgorithmWithDateEntry.getKey());
                // process SignatureAlgorithm, only if not defined explicitly
                if (signatureAlgorithm != null && !explicitlyDefinedSignatureAlgorithms.contains(signatureAlgorithm)) {
                    Date digestAlgoExpirationDate = digestAlgorithmWithDateEntry.getValue();

                    // NOTE: It may be that the same EncryptionAlgo is encountered, therefore the keySizeMap may already exist
                    TreeMap<Integer, Date> keySizeMap = signatureAlgorithmWithKeySizesMap.getOrDefault(signatureAlgorithm, new TreeMap<>());
                    Map<Integer, Date> endDatesMap = getEncryptionAlgorithmKeySizeEndDates(encryptionAlgorithm, algorithmType.getEvaluation());
                    populateKeySizeMap(keySizeMap, endDatesMap);

                    // Ensure that SignatureAlgorithm expires at least as early as DigestAlgorithm, if applicable
                    keySizeMap = getTreeMapWithBottomDates(keySizeMap, digestAlgoExpirationDate);
                    signatureAlgorithmWithKeySizesMap.put(signatureAlgorithm, keySizeMap);
                }
            }
        }

        // Step 3. Build final map between SignatureAlgorithmWithMinKeySize and expiration Date
        final Map<SignatureAlgorithmWithMinKeySize, Date> signatureAlgorithmsMap = new LinkedHashMap<>();
        for (Map.Entry<SignatureAlgorithm, TreeMap<Integer, Date>> entry : signatureAlgorithmWithKeySizesMap.entrySet()) {
            SignatureAlgorithm signatureAlgorithm = entry.getKey();
            for (Map.Entry<Integer, Date> keySizeEntry : entry.getValue().entrySet()) {
                signatureAlgorithmsMap.put(new SignatureAlgorithmWithMinKeySize(signatureAlgorithm, keySizeEntry.getKey()), keySizeEntry.getValue());
            }
        }
        return signatureAlgorithmsMap;
    }

    private SignatureAlgorithm getSignatureAlgorithm(AlgorithmIdentifierType algorithmIdentifier) {
        if (algorithmIdentifier == null) {
            return null;
        }
        List<String> objectIdentifiers = algorithmIdentifier.getObjectIdentifier();
        if (objectIdentifiers != null && !objectIdentifiers.isEmpty()) {
            for (String oid : objectIdentifiers) {
                try {
                    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forOID(oid);
                    if (signatureAlgorithm != null) {
                        /*
                         * Here we check for a potential conflict with the EncryptionAlgorithm definition.
                         * If matching EncryptionAlgorithm is found as well, then we continue with the URIs check.
                         * Example: RSASSA-PSS using the same OID ("1.2.840.113549.1.1.10") as the RSA_SSA_PSS_SHA1_MGF1 Signature Algorithm
                         */
                        EncryptionAlgorithm encryptionAlgorithm = getEncryptionAlgorithm(algorithmIdentifier);
                        if (encryptionAlgorithm == null) {
                            return signatureAlgorithm;
                        }
                    }
                } catch (IllegalArgumentException e) {
                    // continue silently
                }
            }
        }
        // optional
        List<String> uris = algorithmIdentifier.getURI();
        if (uris != null && !uris.isEmpty()) {
            for (String uri : uris) {
                try {
                    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forXML(uri);
                    if (signatureAlgorithm != null) {
                        return signatureAlgorithm;
                    }
                } catch (IllegalArgumentException e) {
                    // continue silently
                }
            }
        }
        return null;
    }

    private EncryptionAlgorithm getEncryptionAlgorithm(AlgorithmIdentifierType algorithmIdentifier) {
        if (algorithmIdentifier == null) {
            return null;
        }
        List<String> objectIdentifiers = algorithmIdentifier.getObjectIdentifier();
        if (objectIdentifiers != null && !objectIdentifiers.isEmpty()) {
            for (String oid : objectIdentifiers) {
                try {
                    // first come, first served policy
                    return EncryptionAlgorithm.forOID(oid);
                } catch (IllegalArgumentException e) {
                    // continue silently
                }
            }
        }
        return null;
    }

    private Map<Integer, Date> getSignatureAlgorithmKeySizeEndDates(SignatureAlgorithm signatureAlgorithm, List<EvaluationType> evaluations) {
        // Encryption algorithm is used for parameters determination
        return getEncryptionAlgorithmKeySizeEndDates(signatureAlgorithm.getEncryptionAlgorithm(), evaluations);
    }

    private Map<Integer, Date> getEncryptionAlgorithmKeySizeEndDates(EncryptionAlgorithm encryptionAlgorithm, List<EvaluationType> evaluations) {
        if (evaluations == null || evaluations.isEmpty()) {
            return Collections.emptyMap();
        }
        final Map<Integer, Date> keySizeEndDates = new LinkedHashMap<>();
        for (EvaluationType evaluation : evaluations) {
            Integer keySize = getKeySize(encryptionAlgorithm, evaluation.getParameter());

            ValidityType validity = evaluation.getValidity();
            if (validity == null) {
                continue;
            }

            Date endDate = getValidityEndDate(validity);
            keySizeEndDates.put(keySize, endDate);
        }
        return keySizeEndDates;
    }

    private Integer getKeySize(EncryptionAlgorithm encryptionAlgorithm, List<ParameterType> parameters) {
        if (parameters == null || parameters.isEmpty()) {
            return 0;
        }

        Integer keySize = 0;
        for (ParameterType parameter : parameters) {
            if (parameter.getMax() != null) {
                LOG.debug("The Max key length parameter is not supported. The value has been skipped.");
            }

            // first come, first served logic
            String name = parameter.getName();
            if (MODULES_LENGTH_PARAMETER.equals(name)) {
                if (EncryptionAlgorithm.RSA.isEquivalent(encryptionAlgorithm)) {
                    return parameter.getMin();
                }

            } else if (PLENGTH_PARAMETER.equals(name)) {
                if (EncryptionAlgorithm.DSA.isEquivalent(encryptionAlgorithm) ||
                        EncryptionAlgorithm.ECDSA.isEquivalent(encryptionAlgorithm) ||
                        EncryptionAlgorithm.EDDSA.isEquivalent(encryptionAlgorithm)) {
                    return parameter.getMin();
                }

            } else if (QLENGTH_PARAMETER.equals(name)) {
                // process silently (not supported)

            } else {
                LOG.warn("Unknown Algorithms Parameter type '{}'!", name);
            }

            // if no known attribute is encountered, return the available key size
            keySize = parameter.getMin();
        }
        return keySize;
    }

    @Override
    public Date getCryptographicSuiteUpdateDate() {
        XMLGregorianCalendar policyIssueDate = securitySuitabilityPolicy.getPolicyIssueDate();
        if (policyIssueDate != null) {
            return policyIssueDate.toGregorianCalendar().getTime();
        }
        return null;
    }

}
