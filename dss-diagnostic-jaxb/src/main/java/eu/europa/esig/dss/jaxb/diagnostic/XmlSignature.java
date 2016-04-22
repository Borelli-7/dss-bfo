//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.7 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.04.21 at 10:29:14 AM CEST 
//


package eu.europa.esig.dss.jaxb.diagnostic;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="ParentId" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="ErrorMessage" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="DateTime" type="{http://www.w3.org/2001/XMLSchema}dateTime" minOccurs="0"/>
 *         &lt;element name="SignatureFormat" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="StructuralValidation" type="{http://dss.esig.europa.eu/validation/diagnostic}StructuralValidationType" minOccurs="0"/>
 *         &lt;element name="BasicSignature" type="{http://dss.esig.europa.eu/validation/diagnostic}BasicSignatureType"/>
 *         &lt;element name="SigningCertificate" type="{http://dss.esig.europa.eu/validation/diagnostic}SigningCertificateType"/>
 *         &lt;element name="CertificateChain" type="{http://dss.esig.europa.eu/validation/diagnostic}CertificateChainType"/>
 *         &lt;element name="ContentType" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="ContentIdentifier" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="ContentHints" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="SignatureProductionPlace" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="Address" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *                   &lt;element name="City" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *                   &lt;element name="StateOrProvince" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *                   &lt;element name="PostalCode" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *                   &lt;element name="CountryName" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *         &lt;element name="CommitmentTypeIndication" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="Identifier" type="{http://www.w3.org/2001/XMLSchema}string" maxOccurs="unbounded" minOccurs="0"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *         &lt;element name="ClaimedRoles" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="ClaimedRole" type="{http://www.w3.org/2001/XMLSchema}string" maxOccurs="unbounded" minOccurs="0"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *         &lt;element name="CertifiedRoles" type="{http://dss.esig.europa.eu/validation/diagnostic}CertifiedRolesType" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="Policy" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="Id" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *                   &lt;element name="Url" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *                   &lt;element name="Notice" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *                   &lt;element name="DigestAlgAndValue" type="{http://dss.esig.europa.eu/validation/diagnostic}DigestAlgAndValueType" minOccurs="0"/>
 *                   &lt;element name="Asn1Processable" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *                   &lt;element name="Identified" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *                   &lt;element name="Status" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *                   &lt;element name="ProcessingError" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *                   &lt;element name="DigestAlgorithmsEqual" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *         &lt;element name="Timestamps" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="Timestamp" type="{http://dss.esig.europa.eu/validation/diagnostic}TimestampType" maxOccurs="unbounded" minOccurs="0"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *         &lt;element name="SignatureScopes">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="SignatureScope" type="{http://dss.esig.europa.eu/validation/diagnostic}SignatureScopeType" maxOccurs="unbounded"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *       &lt;/sequence>
 *       &lt;attribute name="Id" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="Type" type="{http://www.w3.org/2001/XMLSchema}string" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "parentId",
    "errorMessage",
    "dateTime",
    "signatureFormat",
    "structuralValidation",
    "basicSignature",
    "signingCertificate",
    "certificateChain",
    "contentType",
    "contentIdentifier",
    "contentHints",
    "signatureProductionPlace",
    "commitmentTypeIndication",
    "claimedRoles",
    "certifiedRoles",
    "policy",
    "timestamps",
    "signatureScopes"
})
public class XmlSignature {

    @XmlElement(name = "ParentId")
    protected String parentId;
    @XmlElement(name = "ErrorMessage")
    protected String errorMessage;
    @XmlElement(name = "DateTime", type = String.class)
    @XmlJavaTypeAdapter(Adapter1 .class)
    @XmlSchemaType(name = "dateTime")
    protected Date dateTime;
    @XmlElement(name = "SignatureFormat", required = true)
    protected String signatureFormat;
    @XmlElement(name = "StructuralValidation")
    protected XmlStructuralValidationType structuralValidation;
    @XmlElement(name = "BasicSignature", required = true)
    protected XmlBasicSignatureType basicSignature;
    @XmlElement(name = "SigningCertificate", required = true)
    protected XmlSigningCertificateType signingCertificate;
    @XmlElement(name = "CertificateChain", required = true)
    protected XmlCertificateChainType certificateChain;
    @XmlElement(name = "ContentType")
    protected String contentType;
    @XmlElement(name = "ContentIdentifier")
    protected String contentIdentifier;
    @XmlElement(name = "ContentHints")
    protected String contentHints;
    @XmlElement(name = "SignatureProductionPlace")
    protected XmlSignatureProductionPlace signatureProductionPlace;
    @XmlElement(name = "CommitmentTypeIndication")
    protected XmlCommitmentTypeIndication commitmentTypeIndication;
    @XmlElement(name = "ClaimedRoles")
    protected XmlClaimedRoles claimedRoles;
    @XmlElement(name = "CertifiedRoles")
    protected List<XmlCertifiedRolesType> certifiedRoles;
    @XmlElement(name = "Policy")
    protected XmlPolicy policy;
    @XmlElement(name = "Timestamps")
    protected XmlTimestamps timestamps;
    @XmlElement(name = "SignatureScopes", required = true)
    protected XmlSignatureScopes signatureScopes;
    @XmlAttribute(name = "Id", required = true)
    protected String id;
    @XmlAttribute(name = "Type")
    protected String type;

    /**
     * Gets the value of the parentId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getParentId() {
        return parentId;
    }

    /**
     * Sets the value of the parentId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setParentId(String value) {
        this.parentId = value;
    }

    /**
     * Gets the value of the errorMessage property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getErrorMessage() {
        return errorMessage;
    }

    /**
     * Sets the value of the errorMessage property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setErrorMessage(String value) {
        this.errorMessage = value;
    }

    /**
     * Gets the value of the dateTime property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public Date getDateTime() {
        return dateTime;
    }

    /**
     * Sets the value of the dateTime property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDateTime(Date value) {
        this.dateTime = value;
    }

    /**
     * Gets the value of the signatureFormat property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSignatureFormat() {
        return signatureFormat;
    }

    /**
     * Sets the value of the signatureFormat property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSignatureFormat(String value) {
        this.signatureFormat = value;
    }

    /**
     * Gets the value of the structuralValidation property.
     * 
     * @return
     *     possible object is
     *     {@link XmlStructuralValidationType }
     *     
     */
    public XmlStructuralValidationType getStructuralValidation() {
        return structuralValidation;
    }

    /**
     * Sets the value of the structuralValidation property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlStructuralValidationType }
     *     
     */
    public void setStructuralValidation(XmlStructuralValidationType value) {
        this.structuralValidation = value;
    }

    /**
     * Gets the value of the basicSignature property.
     * 
     * @return
     *     possible object is
     *     {@link XmlBasicSignatureType }
     *     
     */
    public XmlBasicSignatureType getBasicSignature() {
        return basicSignature;
    }

    /**
     * Sets the value of the basicSignature property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlBasicSignatureType }
     *     
     */
    public void setBasicSignature(XmlBasicSignatureType value) {
        this.basicSignature = value;
    }

    /**
     * Gets the value of the signingCertificate property.
     * 
     * @return
     *     possible object is
     *     {@link XmlSigningCertificateType }
     *     
     */
    public XmlSigningCertificateType getSigningCertificate() {
        return signingCertificate;
    }

    /**
     * Sets the value of the signingCertificate property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlSigningCertificateType }
     *     
     */
    public void setSigningCertificate(XmlSigningCertificateType value) {
        this.signingCertificate = value;
    }

    /**
     * Gets the value of the certificateChain property.
     * 
     * @return
     *     possible object is
     *     {@link XmlCertificateChainType }
     *     
     */
    public XmlCertificateChainType getCertificateChain() {
        return certificateChain;
    }

    /**
     * Sets the value of the certificateChain property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlCertificateChainType }
     *     
     */
    public void setCertificateChain(XmlCertificateChainType value) {
        this.certificateChain = value;
    }

    /**
     * Gets the value of the contentType property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getContentType() {
        return contentType;
    }

    /**
     * Sets the value of the contentType property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setContentType(String value) {
        this.contentType = value;
    }

    /**
     * Gets the value of the contentIdentifier property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getContentIdentifier() {
        return contentIdentifier;
    }

    /**
     * Sets the value of the contentIdentifier property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setContentIdentifier(String value) {
        this.contentIdentifier = value;
    }

    /**
     * Gets the value of the contentHints property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getContentHints() {
        return contentHints;
    }

    /**
     * Sets the value of the contentHints property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setContentHints(String value) {
        this.contentHints = value;
    }

    /**
     * Gets the value of the signatureProductionPlace property.
     * 
     * @return
     *     possible object is
     *     {@link XmlSignatureProductionPlace }
     *     
     */
    public XmlSignatureProductionPlace getSignatureProductionPlace() {
        return signatureProductionPlace;
    }

    /**
     * Sets the value of the signatureProductionPlace property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlSignatureProductionPlace }
     *     
     */
    public void setSignatureProductionPlace(XmlSignatureProductionPlace value) {
        this.signatureProductionPlace = value;
    }

    /**
     * Gets the value of the commitmentTypeIndication property.
     * 
     * @return
     *     possible object is
     *     {@link XmlCommitmentTypeIndication }
     *     
     */
    public XmlCommitmentTypeIndication getCommitmentTypeIndication() {
        return commitmentTypeIndication;
    }

    /**
     * Sets the value of the commitmentTypeIndication property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlCommitmentTypeIndication }
     *     
     */
    public void setCommitmentTypeIndication(XmlCommitmentTypeIndication value) {
        this.commitmentTypeIndication = value;
    }

    /**
     * Gets the value of the claimedRoles property.
     * 
     * @return
     *     possible object is
     *     {@link XmlClaimedRoles }
     *     
     */
    public XmlClaimedRoles getClaimedRoles() {
        return claimedRoles;
    }

    /**
     * Sets the value of the claimedRoles property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlClaimedRoles }
     *     
     */
    public void setClaimedRoles(XmlClaimedRoles value) {
        this.claimedRoles = value;
    }

    /**
     * Gets the value of the certifiedRoles property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the certifiedRoles property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getCertifiedRoles().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlCertifiedRolesType }
     * 
     * 
     */
    public List<XmlCertifiedRolesType> getCertifiedRoles() {
        if (certifiedRoles == null) {
            certifiedRoles = new ArrayList<XmlCertifiedRolesType>();
        }
        return this.certifiedRoles;
    }

    /**
     * Gets the value of the policy property.
     * 
     * @return
     *     possible object is
     *     {@link XmlPolicy }
     *     
     */
    public XmlPolicy getPolicy() {
        return policy;
    }

    /**
     * Sets the value of the policy property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlPolicy }
     *     
     */
    public void setPolicy(XmlPolicy value) {
        this.policy = value;
    }

    /**
     * Gets the value of the timestamps property.
     * 
     * @return
     *     possible object is
     *     {@link XmlTimestamps }
     *     
     */
    public XmlTimestamps getTimestamps() {
        return timestamps;
    }

    /**
     * Sets the value of the timestamps property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlTimestamps }
     *     
     */
    public void setTimestamps(XmlTimestamps value) {
        this.timestamps = value;
    }

    /**
     * Gets the value of the signatureScopes property.
     * 
     * @return
     *     possible object is
     *     {@link XmlSignatureScopes }
     *     
     */
    public XmlSignatureScopes getSignatureScopes() {
        return signatureScopes;
    }

    /**
     * Sets the value of the signatureScopes property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlSignatureScopes }
     *     
     */
    public void setSignatureScopes(XmlSignatureScopes value) {
        this.signatureScopes = value;
    }

    /**
     * Gets the value of the id property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getId() {
        return id;
    }

    /**
     * Sets the value of the id property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setId(String value) {
        this.id = value;
    }

    /**
     * Gets the value of the type property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getType() {
        return type;
    }

    /**
     * Sets the value of the type property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setType(String value) {
        this.type = value;
    }

}
