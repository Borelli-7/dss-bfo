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
package eu.europa.esig.dss.spi.x509.tsp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.utils.Utils;

class TimestampCertificateSourceTest {

	@Test
	void test() throws Exception {
		String tspB64 = "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";
		byte[] tspBinaries = Utils.fromBase64(tspB64);

		TimeStampToken token = new TimeStampToken(new CMSSignedData(tspBinaries));

		TimestampCertificateSource tcs = new TimestampCertificateSource(token);

		assertEquals(4, tcs.getSignedDataCertificates().size());
	}

}
