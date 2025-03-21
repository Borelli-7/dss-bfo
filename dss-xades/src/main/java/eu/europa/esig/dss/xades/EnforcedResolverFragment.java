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
package eu.europa.esig.dss.xades;

import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.implementations.ResolverFragment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class tests the xpath expression against injection.
 *
 * See https://www.owasp.org/index.php/XPATH_Injection_Java.
 */
public class EnforcedResolverFragment extends ResolverFragment {

	private static final Logger LOG = LoggerFactory.getLogger(EnforcedResolverFragment.class);

	/** The XPath filter */
	private static final String XPATH_CHAR_FILTER = "()='[]:,*/ ";

	/**
	 * Default constructor
	 */
	public EnforcedResolverFragment() {
		// empty
	}

	@Override
	public boolean engineCanResolveURI(ResourceResolverContext context) {
		return checkValueForXpathInjection(context.uriToResolve) && super.engineCanResolveURI(context);
	}

	/**
	 * This method tests the xpath expression against injection
	 * 
	 * @param xpathString
	 *                    the xpath expression to be tested
	 * @return false if the xpath contains forbidden character or if the xpath
	 *         cannot be decoded
	 */
	public boolean checkValueForXpathInjection(String xpathString) {
		if (Utils.isStringNotEmpty(xpathString)) {
			String decodedValue = DSSUtils.decodeURI(xpathString);
			for (char c : decodedValue.toCharArray()) {
				if (XPATH_CHAR_FILTER.indexOf(c) != -1) {
					if (LOG.isDebugEnabled()) {
						LOG.debug("Forbidden char '{}' detected", c);
					}
					return false;
				}
			}
		}
		return true;
	}

}
