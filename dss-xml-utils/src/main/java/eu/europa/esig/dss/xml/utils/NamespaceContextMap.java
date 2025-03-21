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
package eu.europa.esig.dss.xml.utils;

import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * A class for namespace context management. It is used by XPath queries.
 */
public final class NamespaceContextMap implements NamespaceContext {

	/** The map between prefixes and their corresponding URIs */
	private final Map<String, String> prefixMap;

	/** The map between URIs and corresponding prefixes */
	private final Map<String, Set<String>> namespaceMap;

	/**
	 * This is the default constructor
	 */
	public NamespaceContextMap() {
		prefixMap = new HashMap<>();
		namespaceMap = new HashMap<>();
	}

	/**
	 * This method allows to register a namespace and associated prefix. If the prefix exists already it is replaced.
	 *
	 * @param prefix    namespace prefix
	 * @param namespace namespace
	 * @return true if this map did not already contain the specified element
	 */
	public boolean registerNamespace(final String prefix, final String namespace) {
		final String put = prefixMap.put(prefix, namespace);
		createNamespace(prefix, namespace);
		return put == null;
	}

	private void createNamespace(final String prefix, final String namespace) {
		Set<String> prefixes = namespaceMap.computeIfAbsent(namespace, k -> new HashSet<>());
		prefixes.add(prefix);
	}

	/**
	 * Returns a prefix map (a copy)
	 *
	 * @return a map between prefixes and their corresponding uris
	 */
	public Map<String, String> getPrefixMap() {
		return new HashMap<>(prefixMap);
	}

	@Override
	public String getNamespaceURI(String prefix) {
		checkNotNull(prefix);
		String nsURI = prefixMap.get(prefix);
		return nsURI == null ? XMLConstants.NULL_NS_URI : nsURI;
	}

	@Override
	public String getPrefix(String namespaceURI) {
		checkNotNull(namespaceURI);
		Set<String> set = namespaceMap.get(namespaceURI);
		return set == null ? null : set.iterator().next();
	}

	@Override
	public Iterator<String> getPrefixes(String namespaceURI) {
		checkNotNull(namespaceURI);
		Set<String> set = namespaceMap.get(namespaceURI);
		return set.iterator();
	}

	private void checkNotNull(String value) {
		if (value == null) {
			throw new IllegalArgumentException("null");
		}
	}

}
