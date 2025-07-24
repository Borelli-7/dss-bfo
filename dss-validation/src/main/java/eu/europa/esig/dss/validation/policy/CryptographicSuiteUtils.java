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
package eu.europa.esig.dss.validation.policy;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.SignatureAlgorithmWithMinKeySize;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Date;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * This class contains supporting methods for processing a {@code eu.europa.esig.dss.model.policy.CryptographicSuite}
 *
 */
public final class CryptographicSuiteUtils {

    /**
     * Singleton
     */
    private CryptographicSuiteUtils() {
        // empty
    }

    /**
     * Checks if the given {@link SignatureAlgorithm} is reliable (acceptable)
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param signatureAlgorithm {@link SignatureAlgorithm} to check
     * @return TRUE if the algorithm is reliable, FALSE otherwise
     */
    public static boolean isSignatureAlgorithmReliable(CryptographicSuite cryptographicSuite, SignatureAlgorithm signatureAlgorithm) {
        if (cryptographicSuite == null) {
            return true;
        }
        return signatureAlgorithm != null && cryptographicSuite.getAcceptableSignatureAlgorithms().contains(signatureAlgorithm);
    }

    /**
     * Checks if the given {@link DigestAlgorithm} is reliable (acceptable)
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param digestAlgorithm {@link DigestAlgorithm} to check
     * @return TRUE if the algorithm is reliable, FALSE otherwise
     */
    public static boolean isDigestAlgorithmReliable(CryptographicSuite cryptographicSuite, DigestAlgorithm digestAlgorithm) {
        if (cryptographicSuite == null) {
            return true;
        }
        if (digestAlgorithm != null) {
            for (DigestAlgorithm acceptableDigestAlgorithm : cryptographicSuite.getAcceptableDigestAlgorithms()) {
                if (digestAlgorithm == acceptableDigestAlgorithm) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Checks if the {code keyLength} for {@link SignatureAlgorithm} is reliable (acceptable)
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param signatureAlgorithm {@link SignatureAlgorithm} to check key length for
     * @param keyLength {@link String} the key length to be checked
     * @return TRUE if the key length for the algorithm is reliable, FALSE otherwise
     */
    public static boolean isSignatureAlgorithmWithKeySizeReliable(CryptographicSuite cryptographicSuite,
                                                                  SignatureAlgorithm signatureAlgorithm, String keyLength) {
        int keySize = parseKeySize(keyLength);
        return isSignatureAlgorithmWithKeySizeReliable(cryptographicSuite, signatureAlgorithm, keySize);
    }

    /**
     * Checks if the {code keyLength} for {@link SignatureAlgorithm} is reliable (acceptable)
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param signatureAlgorithm {@link SignatureAlgorithm} to check key length for
     * @param keySize {@link Integer} the key length to be checked
     * @return TRUE if the key length for the algorithm is reliable, FALSE otherwise
     */
    public static boolean isSignatureAlgorithmWithKeySizeReliable(CryptographicSuite cryptographicSuite,
                                                                  SignatureAlgorithm signatureAlgorithm, Integer keySize) {
        if (cryptographicSuite == null) {
            return true;
        }
        boolean foundAlgorithm = false;
        if (signatureAlgorithm != null && keySize != 0) {
            for (SignatureAlgorithmWithMinKeySize signatureAlgorithmWithMinKeySize : cryptographicSuite.getAcceptableSignatureAlgorithmsWithMinKeySizes()) {
                int minKeySize = signatureAlgorithmWithMinKeySize.getMinKeySize();
                if (signatureAlgorithm == signatureAlgorithmWithMinKeySize.getSignatureAlgorithm()) {
                    foundAlgorithm = true;
                    if (minKeySize <= keySize) {
                        return true;
                    }
                }
            }
        }
        return !foundAlgorithm;
    }

    private static int parseKeySize(String keyLength) {
        return Utils.isStringDigits(keyLength) ? Integer.parseInt(keyLength) : 0;
    }

    /**
     * Gets an expiration date for the encryption algorithm with name {@code signatureAlgorithm} and {@code keyLength}.
     * Returns null if the expiration date is not defined for the algorithm.
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param signatureAlgorithm {@link SignatureAlgorithm} to get expiration date for
     * @param keyLength {@link String} key length used to sign the token
     * @return {@link Date}
     */
    public static Date getExpirationDate(CryptographicSuite cryptographicSuite,
                                         SignatureAlgorithm signatureAlgorithm, String keyLength) {
        int keySize = parseKeySize(keyLength);
        return getExpirationDate(cryptographicSuite, signatureAlgorithm, keySize);
    }

    /**
     * Gets an expiration date for the encryption algorithm with name {@code signatureAlgorithm} and {@code keyLength}.
     * Returns null if the expiration date is not defined for the algorithm.
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param signatureAlgorithm {@link SignatureAlgorithm} to get expiration date for
     * @param keySize {@link Integer} key length used to sign the token
     * @return {@link Date}
     */
    public static Date getExpirationDate(CryptographicSuite cryptographicSuite,
                                         SignatureAlgorithm signatureAlgorithm, Integer keySize) {
        final TreeMap<Integer, Date> dates = new TreeMap<>();

        Map<SignatureAlgorithmWithMinKeySize, Date> signatureAlgorithmsWithExpirationDates =
                cryptographicSuite.getAcceptableSignatureAlgorithmsWithExpirationDates();
        for (Map.Entry<SignatureAlgorithmWithMinKeySize, Date> entry : signatureAlgorithmsWithExpirationDates.entrySet()) {
            SignatureAlgorithmWithMinKeySize signatureAlgorithmWithMinKeySize = entry.getKey();
            if (signatureAlgorithm == signatureAlgorithmWithMinKeySize.getSignatureAlgorithm()) {
                dates.put(signatureAlgorithmWithMinKeySize.getMinKeySize(), entry.getValue());
            }
        }

        for (SignatureAlgorithmWithMinKeySize signatureAlgorithmWithMinKeySize : cryptographicSuite.getAcceptableSignatureAlgorithmsWithMinKeySizes()) {
            if (signatureAlgorithm == signatureAlgorithmWithMinKeySize.getSignatureAlgorithm()) {
                Map.Entry<Integer, Date> floorEntry = dates.floorEntry(signatureAlgorithmWithMinKeySize.getMinKeySize());
                if (floorEntry == null) {
                    Map.Entry<Integer, Date> ceilingEntry = dates.ceilingEntry(signatureAlgorithmWithMinKeySize.getMinKeySize());
                    if (ceilingEntry != null) {
                        dates.put(signatureAlgorithmWithMinKeySize.getMinKeySize(), ceilingEntry.getValue());
                    }
                }
            }
        }

        Map.Entry<Integer, Date> floorEntry = dates.floorEntry(keySize);
        if (floorEntry == null) {
            return null;
        } else {
            return floorEntry.getValue();
        }
    }

    /**
     * Gets an expiration date for the digest algorithm with name {@code digestAlgoToSearch}.
     * Returns null if the expiration date is not defined for the algorithm.
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param digestAlgorithm {@link DigestAlgorithm} the algorithm to get expiration date for
     * @return {@link Date}
     */
    public static Date getExpirationDate(CryptographicSuite cryptographicSuite, DigestAlgorithm digestAlgorithm) {
        Map<DigestAlgorithm, Date> digestAlgorithmsWithExpirationDates = cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates();
        return digestAlgorithmsWithExpirationDates.get(digestAlgorithm);
    }

    /**
     * This method returns a list of reliable {@code DigestAlgorithm} according to the current validation policy
     * at the given validation time
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param validationTime {@link Date} to verify against
     * @return a list of {@link DigestAlgorithm}s
     */
    public static List<DigestAlgorithm> getReliableDigestAlgorithmsAtTime(CryptographicSuite cryptographicSuite, Date validationTime) {
        final List<DigestAlgorithm> reliableDigestAlgorithms = new ArrayList<>();

        List<DigestAlgorithm> acceptableDigestAlgorithms = cryptographicSuite.getAcceptableDigestAlgorithms();
        Map<DigestAlgorithm, Date> digestAlgorithmsWithExpirationDates = cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates();
        for (Map.Entry<DigestAlgorithm, Date> entry : digestAlgorithmsWithExpirationDates.entrySet()) {
            DigestAlgorithm digestAlgorithm = entry.getKey();
            if (acceptableDigestAlgorithms.contains(digestAlgorithm)) {
                Date expirationDate = entry.getValue();
                if (isReliableAtTime(expirationDate, validationTime)) {
                    reliableDigestAlgorithms.add(digestAlgorithm);
                }
            }
        }

        for (DigestAlgorithm digestAlgorithm : acceptableDigestAlgorithms) {
            if (!reliableDigestAlgorithms.contains(digestAlgorithm)) {
                Date expirationDate = digestAlgorithmsWithExpirationDates.get(digestAlgorithm);
                if (isReliableAtTime(expirationDate, validationTime)) {
                    reliableDigestAlgorithms.add(digestAlgorithm);
                }
            }
        }

        return reliableDigestAlgorithms;
    }

    private static boolean isReliableAtTime(Date expirationDate, Date validationTime) {
        return expirationDate == null || !expirationDate.before(validationTime);
    }

    /**
     * This method returns a list of reliable {@code SignatureAlgorithmWithMinKeySize} according to
     * the current validation policy and at the given time.
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param validationTime {@link Date} to verify against
     * @return a list of {@link SignatureAlgorithmWithMinKeySize}s
     */
    public static List<SignatureAlgorithmWithMinKeySize> getReliableSignatureAlgorithmsWithMinimalKeyLengthAtTime(
            CryptographicSuite cryptographicSuite, Date validationTime) {
        final Map<SignatureAlgorithm, Integer> reliableSignatureAlgorithms = new EnumMap<>(SignatureAlgorithm.class);
        Set<SignatureAlgorithm> processedSignatureAlgorithms = new HashSet<>();

        List<SignatureAlgorithm> acceptableSignatureAlgorithms = cryptographicSuite.getAcceptableSignatureAlgorithms();
        Map<SignatureAlgorithmWithMinKeySize, Date> signatureAlgorithmsWithExpirationDates =
                cryptographicSuite.getAcceptableSignatureAlgorithmsWithExpirationDates();
        for (Map.Entry<SignatureAlgorithmWithMinKeySize, Date> entry : signatureAlgorithmsWithExpirationDates.entrySet()) {
            SignatureAlgorithmWithMinKeySize signatureAlgorithmWithMinKeySize = entry.getKey();
            SignatureAlgorithm signatureAlgorithm = signatureAlgorithmWithMinKeySize.getSignatureAlgorithm();
            int keySize = signatureAlgorithmWithMinKeySize.getMinKeySize();
            if (acceptableSignatureAlgorithms.contains(signatureAlgorithm)) {
                Integer minKeySize = reliableSignatureAlgorithms.get(signatureAlgorithm);
                if (minKeySize == null || minKeySize > keySize) {
                    Date expirationDate = entry.getValue();
                    if (isReliableAtTime(expirationDate, validationTime)) {
                        reliableSignatureAlgorithms.put(signatureAlgorithm, keySize);
                    }
                }
            }
            processedSignatureAlgorithms.add(signatureAlgorithm);
        }

        for (SignatureAlgorithmWithMinKeySize signatureAlgorithmWithMinKeySize : cryptographicSuite.getAcceptableSignatureAlgorithmsWithMinKeySizes()) {
            SignatureAlgorithm signatureAlgorithm = signatureAlgorithmWithMinKeySize.getSignatureAlgorithm();
            int keySize = signatureAlgorithmWithMinKeySize.getMinKeySize();
            if (!processedSignatureAlgorithms.contains(signatureAlgorithm)) {
                reliableSignatureAlgorithms.put(signatureAlgorithm, keySize);

            } else if (reliableSignatureAlgorithms.containsKey(signatureAlgorithm)) {
                Integer minKeySize = reliableSignatureAlgorithms.get(signatureAlgorithm);
                if (minKeySize == null || minKeySize < keySize) {
                    reliableSignatureAlgorithms.put(signatureAlgorithm, keySize);
                }
            }
            processedSignatureAlgorithms.add(signatureAlgorithm);
        }

        for (SignatureAlgorithm signatureAlgorithm : acceptableSignatureAlgorithms) {
            if (!processedSignatureAlgorithms.contains(signatureAlgorithm)) {
                reliableSignatureAlgorithms.put(signatureAlgorithm, 0);
            }
        }

        final List<SignatureAlgorithmWithMinKeySize> result = new ArrayList<>();
        for (Map.Entry<SignatureAlgorithm, Integer> entry : reliableSignatureAlgorithms.entrySet()) {
            result.add(new SignatureAlgorithmWithMinKeySize(entry.getKey(), entry.getValue()));
        }
        return result;
    }

}
