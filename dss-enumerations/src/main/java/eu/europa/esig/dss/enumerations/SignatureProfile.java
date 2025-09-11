package eu.europa.esig.dss.enumerations;

/**
 * Represents a "generic" signature augmentation profile level, such as "*AdES-BASELINE-T".
 *
 */
public enum SignatureProfile {

    /**
     * Basic Signature, incorporating signed and some unsigned qualifying properties when the signature is generated.
     * Example: XAdES-BASELINE-B (ETSI EN 319 132-1)
     */
    BASELINE_B,

    /**
     * Signature with Time, incorporating a trusted token proving that the signature itself actually
     * existed at a certain date and time.
     * Example: XAdES-BASELINE-T (ETSI EN 319 132-1)
     */
    BASELINE_T,

    /**
     * Signature with Long Term Validation Material, incorporating all the material required for validating
     * the signature in the signature document.
     * This level aims to tackle the long term availability of the validation material.
     * Example: XAdES-BASELINE-LT (ETSI EN 319 132-1)
     */
    BASELINE_LT,

    /**
     * Signature with Long Term Availability and Integrity of Validation Material, incorporating electronic time-stamps
     * that allow validation of the signature long time after its generation.
     * This level aims to tackle the long term availability and integrity of the validation material.
     * Example: XAdES-BASELINE-LTA (ETSI EN 319 132-1)
     */
    BASELINE_LTA,

    /**
     * Legacy Basic Signature profile.
     * Example: XAdES-E-BES (ETSI TS 319 132-2)
     */
    EXTENDED_BES,

    /**
     * Legacy Basic Signature profile with SignaturePolicyIdentifier qualifying property.
     * Example: XAdES-E-EPES (ETSI TS 319 132-2)
     */
    EXTENDED_EPES,

    /**
     * Legacy Signature with Time profile with a signature timestamp qualifying property.
     * Example: XAdES-E-T (ETSI TS 319 132-2)
     */
    EXTENDED_T,

    /**
     * Legacy Signature with Long Term Validation Material profile built on top of EXTENDED-T
     * with all the material required for validating the signature in the signature document.
     * Example: XAdES-E-LT
     */
    EXTENDED_LT,

    /**
     * Legacy Signature profile built on top of EXTENDED-T with qualifying properties containing references to
     * certificates and references to certificate status data values.
     * Example: XAdES-E-C (ETSI TS 319 132-2)
     */
    EXTENDED_C,

    /**
     * Legacy Signature profile built on top of EXTENDED-C with one or more
     * qualifying properties containing one or more electronic time-stamps
     * Example: XAdES-E-X (ETSI TS 319 132-2)
     */
    EXTENDED_X,

    /**
     * Legacy Signature profile built on top of EXTENDED-X with qualifying properties
     * that contain certificates and revocation values.
     * Example: XAdES-E-XL (ETSI TS 319 132-2)
     */
    EXTENDED_XL,

    /**
     * Legacy Signature with Long Term Availability and Integrity of Validation Material profile
     * with an archive timestamp qualifying property.
     * Example: XAdES-E-A (ETSI TS 319 132-2)
     */
    EXTENDED_A,

    /**
     * Signature with Evidence Record profile built on top of BASELINE-* or EXTENDED-* profile,
     * containing an evidence record unsigned qualified property.
     * Example: XAdES-E-ERS (ETSI TS 319 132-3)
     */
    EXTENDED_ERS,

    /**
     * Legacy Signature with Long Term Availability and Integrity of Validation Material profile
     * with document security store and one or more document time-stamp (PAdES only).
     * Example: PAdES-E-LTV (ETSI TS 119 142-2)
     */
    EXTENDED_LTV,

    /**
     * Represents an unknown or a not supported signature profile.
     */
    NOT_ETSI

}
