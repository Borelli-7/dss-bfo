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
package eu.europa.esig.dss.validation.process.bbb.cv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks if the signature value is intact
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public class SignatureIntactCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/** Token to check */
	protected final TokenProxy token;

	/** The validation context */
	private final Context context;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param token {@link TokenProxy}
	 * @param context {@link Context}
	 * @param constraint {@link LevelConstraint}
	 */
	public SignatureIntactCheck(I18nProvider i18nProvider, T result, TokenProxy token, Context context, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.token = token;
		this.context = context;
	}

	@Override
	protected boolean process() {
		return token.isSignatureIntact();
	}

	@Override
	protected MessageTag getMessageTag() {
		switch (context) {
			case CERTIFICATE:
				return MessageTag.BBB_CV_ISIC;
			case REVOCATION:
				return MessageTag.BBB_CV_ISIR;
			case TIMESTAMP:
				return MessageTag.BBB_CV_ISIT;
			default:
				return MessageTag.BBB_CV_ISI;
		}
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_CV_ISI_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIG_CRYPTO_FAILURE;
	}

}
