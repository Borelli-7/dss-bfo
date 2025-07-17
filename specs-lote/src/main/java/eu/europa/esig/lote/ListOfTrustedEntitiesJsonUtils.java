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
package eu.europa.esig.lote;

import eu.europa.esig.json.JSONSchemaAbstractUtils;

import java.net.URI;
import java.util.Map;

/**
 * This class contains utils for parsing and validation of the list of Trusted Entities to
 * the ETSI TS 119 602 JSON schema
 *
 */
public final class ListOfTrustedEntitiesJsonUtils extends JSONSchemaAbstractUtils {

    /** LoTE schema URI */
    private static final String SCHEMA_URI =  "19602_json_schema.json";

    private static final String EXTENSION_SCHEMA_URI =  "19602_json_schema_sie.json";

    /** LoTE schema's location */
    private static final String SCHEMA_LOCATION = "/schema/19602_json_schema.json";

    /** LoTE Extension schema's location */
    private static final String EXTENSION_SCHEMA_LOCATION = "/schema/19602_json_schema_sie.json";

    /** Singleton instance */
    private static ListOfTrustedEntitiesJsonUtils singleton;

    /**
     * Empty constructor
     */
    private ListOfTrustedEntitiesJsonUtils() {
        // empty
    }

    /**
     * Returns instance of {@code ListOfTrustedEntitiesJsonUtils}
     *
     * @return {@link ListOfTrustedEntitiesJsonUtils}
     */
    public static ListOfTrustedEntitiesJsonUtils getInstance() {
        if (singleton == null) {
            singleton = new ListOfTrustedEntitiesJsonUtils();
        }
        return singleton;
    }

    @Override
    public String getSchemaURI() {
        return SCHEMA_URI;
    }

    @Override
    public Map<URI, String> getSchemaDefinitions() {
        Map<URI, String> definitions = getJSONSchemaDefinitions();
        definitions.put(URI.create(SCHEMA_URI), SCHEMA_LOCATION);
        definitions.put(URI.create(EXTENSION_SCHEMA_URI), EXTENSION_SCHEMA_LOCATION);
        return definitions;
    }

}
