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
package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.validation.process.CertificatePolicyIdentifiers;
import eu.europa.esig.dss.enumerations.QSCDStatus;

/**
 * Returns QSCD status for a certificate before eIDAS
 *
 */
class QSCDByCertificatePreEIDAS implements QSCDStrategy {

	/** Certificate to get QSCD status for */
	private final CertificateWrapper certificate;

	/**
	 * Default constructor
	 *
	 * @param certificate {@link CertificateWrapper}
	 */
	public QSCDByCertificatePreEIDAS(CertificateWrapper certificate) {
		this.certificate = certificate;
	}

	@Override
	public QSCDStatus getQSCDStatus() {

		// checks in policy id extension
		boolean policyIdSupportedByQSCD = CertificatePolicyIdentifiers.isQCPPlus(certificate);

		// checks in QC statement extension
		boolean qcStatementSupportedByQSCD = certificate.isSupportedByQSCD();

		if (policyIdSupportedByQSCD || qcStatementSupportedByQSCD) {
			return QSCDStatus.QSCD;
		} else {
			return QSCDStatus.NOT_QSCD;
		}
	}

}
