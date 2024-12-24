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
package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * This class checks if the provided certificate token is trusted
 *
 * @param <T> implementation of the block's conclusion
 *
 */
public class RevocationIssuerTrustedCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** Certificate to check */
    private final CertificateWrapper certificate;

    /** The validation time */
    private final Date currentTime;

    /** Identifies the constraint for the revocation data issuer sunset date */
    private final LevelConstraint revocationIssuerSunsetDateConstraint;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param certificate {@link CertificateWrapper} to check
     * @param currentTime {@link Date}
     * @param revocationIssuerSunsetDateConstraint {@link LevelConstraint}
     * @param constraint {@link LevelConstraint}
     */
    public RevocationIssuerTrustedCheck(I18nProvider i18nProvider, T result,
                                        CertificateWrapper certificate, Date currentTime,
                                        LevelConstraint revocationIssuerSunsetDateConstraint, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
        this.currentTime = currentTime;
        this.revocationIssuerSunsetDateConstraint = revocationIssuerSunsetDateConstraint;
    }

    @Override
    protected boolean process() {
        return certificate != null && ValidationProcessUtils.isTrustAnchor(certificate, currentTime, revocationIssuerSunsetDateConstraint);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.PSV_ICRDIT;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.PSV_ICRDIT_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return null;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return null;
    }

    @Override
    protected String buildAdditionalInfo() {
        if (certificate != null) {
            return i18nProvider.getMessage(MessageTag.CERTIFICATE_ID, certificate.getId());
        }
        return null;
    }

}
