/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecordValidator;
import eu.europa.esig.dss.model.DSSDocument;
import org.w3c.dom.Document;

/**
 * Class for validation of an XML Evidence Record (RFC 6283)
 *
 */
public class XMLEvidenceRecordValidator extends DefaultEvidenceRecordValidator {

    /**
     * Empty constructor
     */
    XMLEvidenceRecordValidator() {
        super(new XMLEvidenceRecordAnalyzer());
    }

    /**
     * The default constructor for XMLEvidenceRecordValidator.
     *
     * @param document The instance of {@code DSSDocument} to validate
     */
    public XMLEvidenceRecordValidator(final DSSDocument document) {
        super(new XMLEvidenceRecordAnalyzer(document));
    }

    @Override
    public XMLEvidenceRecordAnalyzer getDocumentAnalyzer() {
        return (XMLEvidenceRecordAnalyzer) super.getDocumentAnalyzer();
    }

    /**
     * Returns the root element of the validating document
     *
     * @return {@link Document}
     */
    public Document getRootElement() {
        return getDocumentAnalyzer().getRootElement();
    }

}