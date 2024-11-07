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
package eu.europa.esig.dss.validation.process.qualification.signature.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationSignatureQualification;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;

/**
 * Checks whether the certificate is qualified at signing time
 *
 */
public class QualifiedCertificateAtSigningTimeCheck extends ChainItem<XmlValidationSignatureQualification> {

	/** Certificate qualification at signing time */
	private final CertificateQualification qualificationAtSigningTime;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlValidationSignatureQualification}
	 * @param qualificationAtSigningTime {@link CertificateQualification}
	 * @param constraint {@link LevelConstraint}
	 */
	public QualifiedCertificateAtSigningTimeCheck(I18nProvider i18nProvider, XmlValidationSignatureQualification result, 
			CertificateQualification qualificationAtSigningTime, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);

		this.qualificationAtSigningTime = qualificationAtSigningTime;
	}

	@Override
	protected boolean process() {
		return qualificationAtSigningTime.isQc();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_QC_AT_ST;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_QC_AT_ST_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return null;
	}

}
