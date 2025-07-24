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
package eu.europa.esig.dss.model.policy;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.Level;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Date;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * This class contains common methods for processing XML and JSON TS 119 322 schemas.
 *
 */
public abstract class Abstract19322CryptographicSuite implements CryptographicSuite {

    private static final Logger LOG = LoggerFactory.getLogger(Abstract19322CryptographicSuite.class);

    /** Key size parameter used by RSA algorithms */
    protected static final String MODULES_LENGTH_PARAMETER = "moduluslength";

    /** P Length key size parameter used by DSA algorithms (supported) */
    protected static final String PLENGTH_PARAMETER = "plength";

    /** Q Length key size parameter used by DSA algorithms (not supported) */
    protected static final String QLENGTH_PARAMETER = "qlength";

    /** Defines global execution level of the cryptographic rules */
    private Level globalLevel = Level.FAIL;

    /** Defines execution level of the acceptability of signature algorithms check */
    private Level acceptableSignatureAlgorithmsLevel;

    /** Defines execution level of the acceptability of the signature algorithms' key length check */
    private Level acceptableSignatureAlgorithmsMinKeySizeLevel;

    /** Defines execution level of the acceptability of digest algorithms check */
    private Level acceptableDigestAlgorithmsLevel;

    /** Defines execution level of the algorithms expiration check */
    private Level algorithmsExpirationDateLevel;

    /** Defines execution level of the algorithms expiration check with expiration occurred after the update of the cryptographic suite */
    private Level algorithmsExpirationTimeAfterPolicyUpdateLevel = Level.WARN;

    /** Cached list of acceptable digest algorithms */
    private List<DigestAlgorithm> acceptableDigestAlgorithms;

    /** Cached list of acceptable signature algorithms */
    private List<SignatureAlgorithm> acceptableSignatureAlgorithms;

    /** Cached list of acceptable signature algorithms with corresponding minimum key sizes */
    private List<SignatureAlgorithmWithMinKeySize> acceptableSignatureAlgorithmsWithMinKeySizes;

    /** Cached list of acceptable digest algorithms with their expiration dates */
    private Map<DigestAlgorithm, Date> acceptableDigestAlgorithmsWithExpirationDates;

    /** Cached list of acceptable signature algorithms with their expiration dates */
    private Map<SignatureAlgorithmWithMinKeySize, Date> acceptableSignatureAlgorithmsWithExpirationDates;

    /**
     * Default constructor
     */
    protected Abstract19322CryptographicSuite() {
        // empty
    }

    @Override
    public Level getLevel() {
        return globalLevel;
    }

    @Override
    public void setLevel(Level level) {
        this.globalLevel = level;
    }

    @Override
    public Level getAcceptableDigestAlgorithmsLevel() {
        return getLevel(acceptableDigestAlgorithmsLevel);
    }

    @Override
    public void setAcceptableDigestAlgorithmsLevel(Level acceptableDigestAlgorithmsLevel) {
        this.acceptableDigestAlgorithmsLevel = acceptableDigestAlgorithmsLevel;
    }

    @Override
    public Level getAcceptableSignatureAlgorithmsLevel() {
        return getLevel(acceptableSignatureAlgorithmsLevel);
    }

    @Override
    public void setAcceptableSignatureAlgorithmsLevel(Level acceptableSignatureAlgorithmsLevel) {
        this.acceptableSignatureAlgorithmsLevel = acceptableSignatureAlgorithmsLevel;
    }

    @Override
    public Level getAcceptableSignatureAlgorithmsMiniKeySizeLevel() {
        return getLevel(acceptableSignatureAlgorithmsMinKeySizeLevel);
    }

    @Override
    public void setAcceptableSignatureAlgorithmsMiniKeySizeLevel(Level acceptableSignatureAlgorithmsMiniKeySizeLevel) {
        this.acceptableSignatureAlgorithmsMinKeySizeLevel = acceptableSignatureAlgorithmsMiniKeySizeLevel;
    }

    @Override
    public Level getAlgorithmsExpirationDateLevel() {
        return getLevel(algorithmsExpirationDateLevel);
    }

    @Override
    public void setAlgorithmsExpirationDateLevel(Level algorithmsExpirationDateLevel) {
        this.algorithmsExpirationDateLevel = algorithmsExpirationDateLevel;
    }

    @Override
    public Level getAlgorithmsExpirationDateAfterUpdateLevel() {
        return algorithmsExpirationTimeAfterPolicyUpdateLevel;
    }

    @Override
    public void setAlgorithmsExpirationTimeAfterPolicyUpdateLevel(Level algorithmsExpirationTimeAfterPolicyUpdateLevel) {
        this.algorithmsExpirationTimeAfterPolicyUpdateLevel = algorithmsExpirationTimeAfterPolicyUpdateLevel;
    }

    private Level getLevel(Level level) {
        // returns global level in case of failure
        return level != null ? level : globalLevel;
    }

    @Override
    public List<DigestAlgorithm> getAcceptableDigestAlgorithms() {
        if (acceptableDigestAlgorithms == null) {
            acceptableDigestAlgorithms = new ArrayList<>(getAcceptableDigestAlgorithmsWithExpirationDates().keySet());
        }
        return acceptableDigestAlgorithms;
    }

    @Override
    public List<SignatureAlgorithm> getAcceptableSignatureAlgorithms() {
        if (acceptableSignatureAlgorithms == null) {
            acceptableSignatureAlgorithms = getAcceptableSignatureAlgorithmsWithMinKeySizes().stream()
                    .map(SignatureAlgorithmWithMinKeySize::getSignatureAlgorithm).collect(Collectors.toList());
        }
        return acceptableSignatureAlgorithms;
    }

    @Override
    public List<SignatureAlgorithmWithMinKeySize> getAcceptableSignatureAlgorithmsWithMinKeySizes() {
        if (acceptableSignatureAlgorithmsWithMinKeySizes == null) {
            Map<SignatureAlgorithm, Integer> signatureAlgorithmWithMinKeySizesMap = new EnumMap<>(SignatureAlgorithm.class);
            for (SignatureAlgorithmWithMinKeySize signatureAlgorithmWithMinKeySize : getAcceptableSignatureAlgorithmsWithExpirationDates().keySet()) {
                SignatureAlgorithm signatureAlgorithm = signatureAlgorithmWithMinKeySize.getSignatureAlgorithm();
                int keySize = signatureAlgorithmWithMinKeySize.getMinKeySize();
                Integer minKeySize = signatureAlgorithmWithMinKeySizesMap.get(signatureAlgorithm);
                if (minKeySize == null || minKeySize > keySize) {
                    minKeySize = keySize;
                }
                signatureAlgorithmWithMinKeySizesMap.put(signatureAlgorithm, minKeySize);
            }
            acceptableSignatureAlgorithmsWithMinKeySizes = signatureAlgorithmWithMinKeySizesMap.entrySet().stream()
                    .map(e -> new SignatureAlgorithmWithMinKeySize(e.getKey(), e.getValue())).collect(Collectors.toList());
        }
        return acceptableSignatureAlgorithmsWithMinKeySizes;
    }

    @Override
    public Map<DigestAlgorithm, Date> getAcceptableDigestAlgorithmsWithExpirationDates() {
        if (acceptableDigestAlgorithmsWithExpirationDates == null) {
            acceptableDigestAlgorithmsWithExpirationDates = buildAcceptableDigestAlgorithmsWithExpirationDates();
        }
        return acceptableDigestAlgorithmsWithExpirationDates;
    }

    @Override
    public Map<SignatureAlgorithmWithMinKeySize, Date> getAcceptableSignatureAlgorithmsWithExpirationDates() {
        if (acceptableSignatureAlgorithmsWithExpirationDates == null) {
            acceptableSignatureAlgorithmsWithExpirationDates = buildAcceptableSignatureAlgorithmsWithExpirationDates();
        }
        return acceptableSignatureAlgorithmsWithExpirationDates;
    }

    /**
     * Builds a list of acceptable digest algorithms with their corresponding expiration times
     *
     * @return a map between {@link DigestAlgorithm}s and their corresponding expiration {@link Date}s
     */
    protected abstract Map<DigestAlgorithm, Date> buildAcceptableDigestAlgorithmsWithExpirationDates();

    /**
     * Builds a list of acceptable signature algorithms with their corresponding expiration times relatively the key sizes
     *
     * @return a map between {@link SignatureAlgorithmWithMinKeySize}s and their corresponding expiration {@link Date}s
     */
    protected abstract Map<SignatureAlgorithmWithMinKeySize, Date> buildAcceptableSignatureAlgorithmsWithExpirationDates();

    /**
     * Finds a {@code SignatureAlgorithm} for the given {@code EncryptionAlgorithm} and {@code DigestAlgorithm} pair
     *
     * @param encryptionAlgorithm {@link EncryptionAlgorithm}
     * @param digestAlgorithm {@link DigestAlgorithm}
     * @return {@link SignatureAlgorithm}
     */
    protected SignatureAlgorithm findSignatureAlgorithm(EncryptionAlgorithm encryptionAlgorithm, DigestAlgorithm digestAlgorithm) {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgorithm);
        if (signatureAlgorithm == null) {
            LOG.trace("Cannot find a SignatureAlgorithm for combination of {} with {}.", encryptionAlgorithm.getName(), digestAlgorithm.getName());
        }
        return signatureAlgorithm;
    }

    /**
     * Populates the {@code keySizeMap} with the {@code endDatesMap} according to the RFC 5698 rules
     * (i.e. the highest expiration Date takes precedence).
     *
     * @param keySizeMap a map of key sizes to be updated
     * @param endDatesMap a map of key sizes to update with
     */
    protected void populateKeySizeMap(TreeMap<Integer, Date> keySizeMap, Map<Integer, Date> endDatesMap) {
        for (Map.Entry<Integer, Date> entry : endDatesMap.entrySet()) {
            Integer keySize = entry.getKey();
            Date keySizeEndDate = entry.getValue();

            // if there is an entry with a longer deprecation date, we need to re-use the existing entry. See RFC 5698
            Map.Entry<Integer, Date> floorEntry = keySizeMap.floorEntry(keySize);
            if (floorEntry != null) {
                Date currentEndDate = floorEntry.getValue();
                if (currentEndDate == null || (keySizeEndDate != null && currentEndDate.after(keySizeEndDate))) {
                    keySizeEndDate = currentEndDate;
                }
            }

            // evaluate existing keySize entries, and "extend" with a longer expiration date, if applicable
            Map.Entry<Integer, Date> higherEntry = keySizeMap.higherEntry(keySize);
            if (higherEntry != null) {
                Date currentEndDate = higherEntry.getValue();
                if (currentEndDate != null && (keySizeEndDate == null || currentEndDate.before(keySizeEndDate))) {
                    keySizeMap.put(higherEntry.getKey(), keySizeEndDate);
                }
            }

            keySizeMap.put(keySize, keySizeEndDate);
        }
    }

    /**
     * Returns the map with values changed to the "bottom" between the original values within the map and 
     * the provided {@code expirationDate}
     * 
     * @param keySizeExpirationMap a map of key sizes to be updated
     * @param expirationDate {@link Date} to update with
     * @return updated key map
     */
    protected TreeMap<Integer, Date> getTreeMapWithBottomDates(TreeMap<Integer, Date> keySizeExpirationMap, Date expirationDate) {
        if (expirationDate == null) {
            return keySizeExpirationMap;
        }
        final TreeMap<Integer, Date> updatedKeySizeMap = new TreeMap<>();
        for (Map.Entry<Integer, Date> keySizeWithDate : keySizeExpirationMap.entrySet()) {
            Date keySizeExpiration = keySizeWithDate.getValue();
            if (keySizeExpiration == null || keySizeExpiration.after(expirationDate)) {
                keySizeExpiration = expirationDate;
            }
            updatedKeySizeMap.put(keySizeWithDate.getKey(), keySizeExpiration);
        }
        return updatedKeySizeMap;
    }

}
