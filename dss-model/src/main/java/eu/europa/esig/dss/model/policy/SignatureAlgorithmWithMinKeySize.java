package eu.europa.esig.dss.model.policy;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;

import java.io.Serializable;
import java.util.Objects;

/**
 * Defines a {@code eu.europa.esig.dss.enumerations.SignatureAlgorithm} with a minimum key size
 *
 */
public class SignatureAlgorithmWithMinKeySize implements Serializable {

    private static final long serialVersionUID = 613854187099274464L;

    /** The Signature algorithm */
    private final SignatureAlgorithm signatureAlgorithm;

    /** The minimal accepted key size */
    private final int minKeySize;

    /**
     * Default constructor
     *
     * @param signatureAlgorithm {@link SignatureAlgorithm}
     * @param minKeySize integer key size. 0 when not defined
     */
    public SignatureAlgorithmWithMinKeySize(final SignatureAlgorithm signatureAlgorithm, int minKeySize) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.minKeySize = minKeySize;
    }

    /**
     * Gets Signature algorithm
     *
     * @return {@link SignatureAlgorithm}
     */
    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * Gets the minimum key size value
     *
     * @return key size
     */
    public int getMinKeySize() {
        return minKeySize;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        SignatureAlgorithmWithMinKeySize that = (SignatureAlgorithmWithMinKeySize) object;
        return minKeySize == that.minKeySize
                && signatureAlgorithm == that.signatureAlgorithm;
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(signatureAlgorithm);
        result = 31 * result + minKeySize;
        return result;
    }

    @Override
    public String toString() {
        return "SignatureAlgorithmWithMinKeySize [" +
                "signatureAlgorithm=" + signatureAlgorithm +
                ", minKeySize=" + minKeySize +
                ']';
    }

}