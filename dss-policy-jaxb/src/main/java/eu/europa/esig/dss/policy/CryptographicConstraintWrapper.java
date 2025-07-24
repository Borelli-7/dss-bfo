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
package eu.europa.esig.dss.policy;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.EncryptionAlgorithmWithMinKeySize;
import eu.europa.esig.dss.model.policy.SignatureAlgorithmWithMinKeySize;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.AlgoExpirationDate;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.ListAlgo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

/**
 * Wraps a {@code CryptographicConstraint} of the DSS JAXB validation policy implementation
 * into a {@code CryptographicConstraintWrapper}
 *
 */
public class CryptographicConstraintWrapper extends LevelConstraintWrapper implements CryptographicSuite {

    private static final Logger LOG = LoggerFactory.getLogger(CryptographicConstraintWrapper.class);

    /** The default date format */
    private static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd";

    /** The default timezone (UTC) */
    private static final TimeZone UTC = TimeZone.getTimeZone("UTC");

    /** Cached list of acceptable digest algorithms */
    private List<DigestAlgorithm> acceptableDigestAlgorithms;

    /** Cached list of acceptable digest algorithms with their expiration dates */
    private Map<DigestAlgorithm, Date> acceptableDigestAlgorithmsWithExpirationDates;

    /** Cached list of acceptable signature algorithms */
    private List<SignatureAlgorithm> acceptableSignatureAlgorithms;

    /** Cached list of acceptable signature algorithms with corresponding minimum key sizes */
    private List<SignatureAlgorithmWithMinKeySize> acceptableSignatureAlgorithmsWithMinKeySizes;

    /** Cached list of acceptable signature algorithms with their expiration dates */
    private Map<SignatureAlgorithmWithMinKeySize, Date> acceptableSignatureAlgorithmsWithExpirationDates;

    /**
     * Constructor to create an empty instance of Cryptographic constraints
     */
    public CryptographicConstraintWrapper() {
        super(null);
    }

    /**
     * Default constructor
     *
     * @param constraint {@link CryptographicConstraint}
     */
    public CryptographicConstraintWrapper(CryptographicConstraint constraint) {
        super(constraint);
    }

    @Override
    public String getPolicyName() {
        return "DSS Cryptographic Constraint";
    }

    @Override
    public List<DigestAlgorithm> getAcceptableDigestAlgorithms() {
        if (acceptableDigestAlgorithms == null) {
            acceptableDigestAlgorithms = new ArrayList<>();
            if (constraint != null) {
                ListAlgo acceptableDigestAlgos = ((CryptographicConstraint) constraint).getAcceptableDigestAlgo();
                if (acceptableDigestAlgos != null) {
                    for (Algo algo : acceptableDigestAlgos.getAlgos()) {
                        DigestAlgorithm digestAlgorithm = toDigestAlgorithm(algo.getValue());
                        if (digestAlgorithm != null) {
                            acceptableDigestAlgorithms.add(digestAlgorithm);
                        }
                    }
                }
            }
        }
        return acceptableDigestAlgorithms;
    }

    @Override
    public List<SignatureAlgorithm> getAcceptableSignatureAlgorithms() {
        if (acceptableSignatureAlgorithms == null) {
            acceptableSignatureAlgorithms = new ArrayList<>();

            List<DigestAlgorithm> digestAlgorithms = getAcceptableDigestAlgorithms();
            List<EncryptionAlgorithm> encryptionAlgorithms = getAcceptableEncryptionAlgorithms();
            for (EncryptionAlgorithm encryptionAlgorithm : encryptionAlgorithms) {
                for (DigestAlgorithm digestAlgorithm : digestAlgorithms) {
                    SignatureAlgorithm signatureAlgorithm = findSignatureAlgorithm(encryptionAlgorithm, digestAlgorithm);
                    if (signatureAlgorithm != null) {
                        acceptableSignatureAlgorithms.add(signatureAlgorithm);
                    }
                }
            }
        }
        return acceptableSignatureAlgorithms;
    }

    /**
     * Gets a list of Encryption algorithms accepted by the current policy
     *
     * @return a list of {@link EncryptionAlgorithm}
     */
    protected List<EncryptionAlgorithm> getAcceptableEncryptionAlgorithms() {
        List<EncryptionAlgorithm> acceptableEncryptionAlgorithms = new ArrayList<>();
        if (constraint != null) {
            ListAlgo acceptableEncryptionAlgos = ((CryptographicConstraint) constraint).getAcceptableEncryptionAlgo();
            if (acceptableEncryptionAlgos != null) {
                for (Algo algo : acceptableEncryptionAlgos.getAlgos()) {
                    EncryptionAlgorithm encryptionAlgorithm = toEncryptionAlgorithm(algo.getValue());
                    if (encryptionAlgorithm != null) {
                        acceptableEncryptionAlgorithms.add(encryptionAlgorithm);
                    }
                }
            }
        }
        return acceptableEncryptionAlgorithms;
    }

    @Override
    public List<SignatureAlgorithmWithMinKeySize> getAcceptableSignatureAlgorithmsWithMinKeySizes() {
        if (acceptableSignatureAlgorithmsWithMinKeySizes == null) {
            acceptableSignatureAlgorithmsWithMinKeySizes = new ArrayList<>();

            List<DigestAlgorithm> digestAlgorithms = getAcceptableDigestAlgorithms();
            List<EncryptionAlgorithmWithMinKeySize> encryptionAlgorithmsWithMinKeySizes = getAcceptableEncryptionAlgorithmsWithMinKeySizes();
            for (EncryptionAlgorithmWithMinKeySize encryptionAlgorithmWithMinKeySize : encryptionAlgorithmsWithMinKeySizes) {
                EncryptionAlgorithm encryptionAlgorithm = encryptionAlgorithmWithMinKeySize.getEncryptionAlgorithm();
                for (DigestAlgorithm digestAlgorithm : digestAlgorithms) {
                    SignatureAlgorithm signatureAlgorithm = findSignatureAlgorithm(encryptionAlgorithm, digestAlgorithm);
                    if (signatureAlgorithm != null) {
                        acceptableSignatureAlgorithmsWithMinKeySizes.add(new SignatureAlgorithmWithMinKeySize(signatureAlgorithm, encryptionAlgorithmWithMinKeySize.getMinKeySize()));
                    }
                }
            }
        }
        return acceptableSignatureAlgorithmsWithMinKeySizes;
    }

    /**
     * Gets a list of acceptable encryption algorithms with the corresponding minimum key sizes
     *
     * @return a list of {@link EncryptionAlgorithmWithMinKeySize}
     */
    protected List<EncryptionAlgorithmWithMinKeySize> getAcceptableEncryptionAlgorithmsWithMinKeySizes() {
        List<EncryptionAlgorithmWithMinKeySize> acceptableEncryptionAlgorithmsWithMinKeySizes = new ArrayList<>();
        if (constraint != null) {
            ListAlgo miniPublicKeySizes = ((CryptographicConstraint) constraint).getMiniPublicKeySize();
            if (miniPublicKeySizes != null) {
                for (Algo algo : miniPublicKeySizes.getAlgos()) {
                    EncryptionAlgorithm encryptionAlgorithm = toEncryptionAlgorithm(algo.getValue());
                    if (encryptionAlgorithm != null) {
                        acceptableEncryptionAlgorithmsWithMinKeySizes.add(new EncryptionAlgorithmWithMinKeySize(encryptionAlgorithm, algo.getSize()));
                    }
                }
            }
        }
        return acceptableEncryptionAlgorithmsWithMinKeySizes;
    }

    @Override
    public Map<DigestAlgorithm, Date> getAcceptableDigestAlgorithmsWithExpirationDates() {
        if (acceptableDigestAlgorithmsWithExpirationDates == null) {
            acceptableDigestAlgorithmsWithExpirationDates = new LinkedHashMap<>();
            if (constraint != null) {
                AlgoExpirationDate algoExpirationDates = ((CryptographicConstraint) constraint).getAlgoExpirationDate();
                if (algoExpirationDates != null) {
                    SimpleDateFormat dateFormat = getUsedDateFormat(algoExpirationDates);
                    for (Algo algo: algoExpirationDates.getAlgos()) {
                        final DigestAlgorithm digestAlgorithm = toDigestAlgorithm(algo.getValue());
                        if (digestAlgorithm != null) {
                            Date expirationDate = getDate(algo, dateFormat);
                            acceptableDigestAlgorithmsWithExpirationDates.put(digestAlgorithm, expirationDate);
                        }
                    }
                }
                // For all accepted Digest Algos without expiration dates
                ListAlgo acceptableDigestAlgo = ((CryptographicConstraint) constraint).getAcceptableDigestAlgo();
                if (acceptableDigestAlgo != null) {
                    for (Algo algo: acceptableDigestAlgo.getAlgos()) {
                        final DigestAlgorithm digestAlgorithm = toDigestAlgorithm(algo.getValue());
                        if (digestAlgorithm != null && !acceptableDigestAlgorithmsWithExpirationDates.containsKey(digestAlgorithm)) {
                            acceptableDigestAlgorithmsWithExpirationDates.put(digestAlgorithm, null);
                        }
                    }
                }
            }
        }
        return acceptableDigestAlgorithmsWithExpirationDates;
    }

    private DigestAlgorithm toDigestAlgorithm(String algorithmName) {
        try {
            return DigestAlgorithm.forName(algorithmName);
        } catch (IllegalArgumentException e) {
            // continue silently
            return null;
        }
    }

    private SimpleDateFormat getUsedDateFormat(AlgoExpirationDate expirations) {
        SimpleDateFormat sdf = new SimpleDateFormat(expirations.getFormat() != null ? expirations.getFormat() : DEFAULT_DATE_FORMAT);
        sdf.setTimeZone(UTC);
        return sdf;
    }

    private Date getDate(Algo algo, SimpleDateFormat format) {
        if (algo != null) {
            return getDate(algo.getDate(), format);
        }
        return null;
    }

    private Date getDate(String dateString, SimpleDateFormat format) {
        if (dateString != null) {
            try {
                return format.parse(dateString);
            } catch (ParseException e) {
                LOG.warn("Unable to parse '{}' with format '{}'", dateString, format);
            }
        }
        return null;
    }

    @Override
    public Map<SignatureAlgorithmWithMinKeySize, Date> getAcceptableSignatureAlgorithmsWithExpirationDates() {
        if (acceptableSignatureAlgorithmsWithExpirationDates == null) {
            acceptableSignatureAlgorithmsWithExpirationDates = new LinkedHashMap<>();

            Map<DigestAlgorithm, Date> digestAlgorithmsWithExpirationDates = getAcceptableDigestAlgorithmsWithExpirationDates();
            Map<EncryptionAlgorithmWithMinKeySize, Date> encryptionAlgorithmsExpirationMap = getAcceptableEncryptionAlgorithmsWithExpirationDates();
            for (Map.Entry<EncryptionAlgorithmWithMinKeySize, Date> entry : encryptionAlgorithmsExpirationMap.entrySet()) {
                EncryptionAlgorithmWithMinKeySize encryptionAlgorithmWithMinKeySize = entry.getKey();
                EncryptionAlgorithm encryptionAlgorithm = encryptionAlgorithmWithMinKeySize.getEncryptionAlgorithm();
                for (Map.Entry<DigestAlgorithm, Date> digestAlgorithmWithExpirationDate : digestAlgorithmsWithExpirationDates.entrySet()) {
                    SignatureAlgorithm signatureAlgorithm = findSignatureAlgorithm(encryptionAlgorithm, digestAlgorithmWithExpirationDate.getKey());
                    if (signatureAlgorithm != null) {
                        // take the earliest expiration time
                        Date expirationDate = digestAlgorithmWithExpirationDate.getValue();
                        Date encryptionAlgoExpiration = entry.getValue();
                        if (expirationDate == null || (encryptionAlgoExpiration != null && encryptionAlgoExpiration.before(expirationDate))) {
                            expirationDate = encryptionAlgoExpiration;
                        }
                        acceptableSignatureAlgorithmsWithExpirationDates.put(
                                new SignatureAlgorithmWithMinKeySize(signatureAlgorithm, encryptionAlgorithmWithMinKeySize.getMinKeySize()), expirationDate);
                    }
                }
            }
        }
        return acceptableSignatureAlgorithmsWithExpirationDates;
    }

    private SignatureAlgorithm findSignatureAlgorithm(EncryptionAlgorithm encryptionAlgorithm, DigestAlgorithm digestAlgorithm) {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgorithm);
        if (signatureAlgorithm == null) {
            LOG.trace("Cannot find a SignatureAlgorithm for combination of {} with {}.", encryptionAlgorithm.getName(), digestAlgorithm.getName());
        }
        return signatureAlgorithm;
    }

    /**
     * Gets a map between {@code EncryptionAlgorithmWithMinKeySize} and their corresponding expiration dates
     *
     * @return a map between {@code EncryptionAlgorithmWithMinKeySize} and {@code Date}
     */
    protected Map<EncryptionAlgorithmWithMinKeySize, Date> getAcceptableEncryptionAlgorithmsWithExpirationDates() {
        Set<EncryptionAlgorithm> addedEncryptionAlgos = new HashSet<>();
        Map<EncryptionAlgorithmWithMinKeySize, Date> acceptableEncryptionAlgorithmsWithExpirationDates = new LinkedHashMap<>();
        if (constraint != null) {
            AlgoExpirationDate algoExpirationDates = ((CryptographicConstraint) constraint).getAlgoExpirationDate();
            if (algoExpirationDates != null) {
                SimpleDateFormat dateFormat = getUsedDateFormat(algoExpirationDates);
                for (Algo algo: algoExpirationDates.getAlgos()) {
                    final EncryptionAlgorithm encryptionAlgorithm = toEncryptionAlgorithm(algo.getValue());
                    if (encryptionAlgorithm != null) {
                        Date expirationDate = getDate(algo, dateFormat);
                        acceptableEncryptionAlgorithmsWithExpirationDates.put(new EncryptionAlgorithmWithMinKeySize(encryptionAlgorithm, algo.getSize()), expirationDate);
                        addedEncryptionAlgos.add(encryptionAlgorithm);
                    }
                }
                // For all accepted Encryption Algos without expiration dates
                ListAlgo miniPublicKeySize = ((CryptographicConstraint) constraint).getMiniPublicKeySize();
                if (miniPublicKeySize != null) {
                    for (Algo algo: miniPublicKeySize.getAlgos()) {
                        final EncryptionAlgorithm encryptionAlgorithm = toEncryptionAlgorithm(algo.getValue());
                        if (encryptionAlgorithm != null && !addedEncryptionAlgos.contains(encryptionAlgorithm)) {
                            acceptableEncryptionAlgorithmsWithExpirationDates.put(new EncryptionAlgorithmWithMinKeySize(encryptionAlgorithm, algo.getSize()), null);
                            addedEncryptionAlgos.add(encryptionAlgorithm);
                        }
                    }
                }
                ListAlgo acceptableEncryptionAlgos = ((CryptographicConstraint) constraint).getAcceptableEncryptionAlgo();
                if (acceptableEncryptionAlgos != null) {
                    for (Algo algo: acceptableEncryptionAlgos.getAlgos()) {
                        final EncryptionAlgorithm encryptionAlgorithm = toEncryptionAlgorithm(algo.getValue());
                        if (encryptionAlgorithm != null && !addedEncryptionAlgos.contains(encryptionAlgorithm)) {
                            acceptableEncryptionAlgorithmsWithExpirationDates.put(new EncryptionAlgorithmWithMinKeySize(encryptionAlgorithm, 0), null);
                            addedEncryptionAlgos.add(encryptionAlgorithm);
                        }
                    }
                }
            }
        }
        return acceptableEncryptionAlgorithmsWithExpirationDates;
    }

    private EncryptionAlgorithm toEncryptionAlgorithm(String algorithmName) {
        try {
            return EncryptionAlgorithm.forName(algorithmName);
        } catch (IllegalArgumentException e) {
            // continue silently
            return null;
        }
    }

    @Override
    public void setLevel(Level level) {
        if (constraint != null) {
            constraint.setLevel(level);
        }
    }

    @Override
    public Level getAcceptableSignatureAlgorithmsLevel() {
        if (constraint != null) {
            return getCryptographicLevel(((CryptographicConstraint) constraint).getAcceptableEncryptionAlgo());
        }
        return null;
    }

    @Override
    public void setAcceptableSignatureAlgorithmsLevel(Level acceptableEncryptionAlgorithmsLevel) {
        if (constraint != null) {
            ListAlgo acceptableEncryptionAlgo = ((CryptographicConstraint) constraint).getAcceptableEncryptionAlgo();
            if (acceptableEncryptionAlgo != null) {
                acceptableEncryptionAlgo.setLevel(acceptableEncryptionAlgorithmsLevel);
            }
        }
    }

    @Override
    public Level getAcceptableSignatureAlgorithmsMiniKeySizeLevel() {
        if (constraint != null) {
            return getCryptographicLevel(((CryptographicConstraint) constraint).getMiniPublicKeySize());
        }
        return null;
    }

    @Override
    public void setAcceptableSignatureAlgorithmsMiniKeySizeLevel(Level acceptableEncryptionAlgorithmsMiniKeySizeLevel) {
        if (constraint != null) {
            ListAlgo miniPublicKeySize = ((CryptographicConstraint) constraint).getMiniPublicKeySize();
            if (miniPublicKeySize != null) {
                miniPublicKeySize.setLevel(acceptableEncryptionAlgorithmsMiniKeySizeLevel);
            }
        }
    }

    @Override
    public Level getAcceptableDigestAlgorithmsLevel() {
        if (constraint != null) {
            return getCryptographicLevel(((CryptographicConstraint) constraint).getAcceptableDigestAlgo());
        }
        return null;
    }

    @Override
    public void setAcceptableDigestAlgorithmsLevel(Level acceptableDigestAlgorithmsLevel) {
        if (constraint != null) {
            ListAlgo acceptableDigestAlgo = ((CryptographicConstraint) constraint).getAcceptableDigestAlgo();
            if (acceptableDigestAlgo != null) {
                acceptableDigestAlgo.setLevel(acceptableDigestAlgorithmsLevel);
            }
        }
    }

    @Override
    public Level getAlgorithmsExpirationDateLevel() {
        if (constraint != null) {
            return getCryptographicLevel(((CryptographicConstraint) constraint).getAlgoExpirationDate());
        }
        return null;
    }

    @Override
    public void setAlgorithmsExpirationDateLevel(Level algorithmsExpirationDateLevel) {
        if (constraint != null) {
            AlgoExpirationDate algoExpirationDate = ((CryptographicConstraint) constraint).getAlgoExpirationDate();
            if (algoExpirationDate != null) {
                algoExpirationDate.setLevel(algorithmsExpirationDateLevel);
            }
        }
    }

    @Override
    public Level getAlgorithmsExpirationDateAfterUpdateLevel() {
        if (constraint != null) {
            AlgoExpirationDate algoExpirationDate = ((CryptographicConstraint) constraint).getAlgoExpirationDate();
            if (algoExpirationDate != null && algoExpirationDate.getLevelAfterUpdate() != null) {
                return algoExpirationDate.getLevelAfterUpdate();
            }
            return getCryptographicLevel(algoExpirationDate);
        }
        return null;
    }

    @Override
    public void setAlgorithmsExpirationTimeAfterPolicyUpdateLevel(Level algorithmsExpirationTimeAfterPolicyUpdateLevel) {
        if (constraint != null) {
            AlgoExpirationDate algoExpirationDate = ((CryptographicConstraint) constraint).getAlgoExpirationDate();
            if (algoExpirationDate != null) {
                algoExpirationDate.setLevelAfterUpdate(algorithmsExpirationTimeAfterPolicyUpdateLevel);
            }
        }
    }

    @Override
    public Date getCryptographicSuiteUpdateDate() {
        if (constraint != null) {
            AlgoExpirationDate algoExpirationDates = ((CryptographicConstraint) constraint).getAlgoExpirationDate();
            if (algoExpirationDates != null) {
                final SimpleDateFormat dateFormat = getUsedDateFormat(algoExpirationDates);
                return getDate(algoExpirationDates.getUpdateDate(), dateFormat);
            }
        }
        return null;
    }

    private Level getCryptographicLevel(LevelConstraint cryptoConstraint) {
        if (cryptoConstraint != null && cryptoConstraint.getLevel() != null) {
            return cryptoConstraint.getLevel();
        }
        // return global Level if target level is not present
        return getLevel();
    }

}
